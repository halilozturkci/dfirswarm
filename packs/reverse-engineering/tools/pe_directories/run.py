#!/usr/bin/env python3
"""Read the data directories of a PE file that pe_info declares and does not read, and never run the file.

pe_info validates the headers, sections and imports and says which directories exist. This tool reads the directories it
leaves unread, each through checked ranges (an RVA is turned into a file offset only through a section that holds file
bytes there, and a field is read only from bytes the structure that contains it holds):

    exports        the export directory: every exported function with its ordinal, its RVA, its name where it has one
                   and its forwarder string where the RVA points back into the directory
    delay imports  the delay-load descriptors with their library names and function names or ordinals
    TLS            the TLS directory and its callback array: the callbacks run before the entry point, each is listed
                   with the section that holds it
    resources      the resource tree (type, name or id, language), each leaf's RVA, file offset and size; the version
                   information (the fixed file version and the string table, a few well-known keys by value, the rest
                   by name) and the manifest's requested execution level
    CLR header     the runtime header's version, flags, entry point token and directories, and the metadata root: its
                   version string and the names and sizes of its streams. The metadata tables are not read, so there
                   is no assembly name here
    debug          the debug directory: each entry's type and time, and for a CodeView entry the PDB identity and path
    Rich header    the decoded entries of the Rich header, if there is one: raw product ids, build numbers and counts

A string out of the file (an export name, a resource string, a PDB path) is evidence the file supplies: it is withheld
from the answer when it is shaped like a token, and the whole is kept only when the caller asks for write_values in a job.
Nothing is executed, nothing is verified (no signature, no strong name), and nothing is named a family, a compiler or a
version beyond what the header's own numbers say.
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
import xml.parsers.expat
from datetime import datetime, timezone
from pathlib import Path

TOOL = {"name": "pe_directories", "version": 1}
PARSER = "pe_directories/1"
NOTE = ("Static structure only. A directory shows what the file declares to its loader and tools, not what the code does: an export, a delay-load "
        "import, a TLS callback or a resource is a declaration, and a strong-name flag or a PDB path is a claim. Read `status`, `problems` and `coverage` "
        "first: they say what was read and what was not. A string out of the file is shown with each backslash written twice and each control character as \\xNN.")

MAX_LIMIT = 20000                  # the most rows of one table the answer may hold (a longer table is in its file; the rows are withheld as the reading adds them)
DEFAULT_LIMIT = 1000
DEFAULT_STREAM = 16 << 20           # bytes one resource or metadata structure may be read as
DEFAULT_TOTAL = 128 << 20
DEFAULT_SECONDS = 70                # the reading clock; the answer is built after it (HARD_SECONDS below), inside the manifest's 120 s
MAX_SECONDS = 90
MAX_SECTIONS = 65535
MAX_EXPORTS = 1_000_000
MAX_DELAY_DESCRIPTORS = 4096
MAX_DELAY_FUNCTIONS = 1_000_000          # names and ordinals listed over all the delay-load descriptors together
MAX_RESOURCES = 200000
MAX_TLS_CALLBACKS = 1024
MAX_DEBUG_ENTRIES = 1024
MAX_PROBLEMS = 100
NAME_CAP = 4096
MAX_STREAM_HEADERS = 4096
MAX_VERSION_STRINGS = 4096
OVERLAP_LOOK_BACK = 64
GUID_TEXT = re.compile(rb"[A-Za-z0-9_+/=-]{9,}")
GUID_CHARS = frozenset(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_+/=-")


def guid_is_text(raw):
    """Sixteen bytes that hold a run of nine token characters, or ten such characters in all (text split by a NUL every few bytes, so that
    no run is nine long), are text placed where an identifier goes. Uniform random bytes reach ten about once in 420 ids (a class id
    of the Office formats, mostly zero bytes, never does): such an id is withheld, by its length."""
    return bool(GUID_TEXT.search(raw)) or sum(1 for b in raw if b in GUID_CHARS) >= 10
MAX_EXTRACT = 64
SPILL_FLOOR = 100                   # no list in the answer is longer than the larger of `limit` and this: a longer one is in a file, whole
HEAD_BYTES = 1024
PAGE = 1 << 16

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

# Strings the tool made itself and registered (a page file's path, the names file's path, a CodeView GUID that is not text): only these, and
# only under one of these keys, leave unchanged. Anything else, under any key, is withheld like any string out of the file: a key here
# is never a way round the withholding for a string built from the file's bytes.
SAFE_KEYS = {"guid", "all_results", "withheld_names_file"}
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
        page = LosslessPage("pe_directories-list", [self.ctx.key, "list", self.n], 0)
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

    NAME = "pe-directories-values.jsonl"

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
                "file, not a sealed secret output. Run this as job_run tool=pe_directories with "
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

    NAME = "pe-directories-withheld-names"

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
            self.pages[name] = LosslessPage("pe_directories-" + name, [self.key, name], self.limit)
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


NAME_SHOWN = 512                    # characters of an export, forwarder or delay-load name the answer shows; a longer one is given by its length
NAME_KINDS = {"export_image_name", "export_forwarder", "export_name", "delay_import_library", "delay_import_function"}


def show(ctx, what, text, at, finding=None):
    """A string out of the file as it may be printed (shown_at); the whole goes to the values file when it was asked for. A name of the
    export and delay-load tables longer than NAME_SHOWN is given by its length only (no linker writes one that long, and a file that
    holds thousands of them must not cost the sanitiser a pass over each)."""
    if what in NAME_KINDS and len(text) > NAME_SHOWN:
        shown = "<a name of %d characters: longer than the %d shown, so not shown>" % (len(text), NAME_SHOWN)
    else:
        shown = shown_at(ctx, text, at)
    if shown != cell(text):
        ctx.names.add(text, shown, what)
    if finding is not None:
        ctx.values.add(finding, {"field": what, "file_offset": at}, text)
    return shown


class DoctypeRefused(Exception):
    pass


def xml_elements(data, on_element):
    """Hand every element to `on_element(local_name, attrs)` as it is read, namespaces dropped; a DOCTYPE is refused, so no entity is
    expanded. Raises DoctypeRefused or xml.parsers.expat.ExpatError."""
    parser = xml.parsers.expat.ParserCreate(namespace_separator=" ")
    parser.SetParamEntityParsing(xml.parsers.expat.XML_PARAM_ENTITY_PARSING_NEVER)

    def start(name, attrs):
        on_element(name.rpartition(" ")[2], {k.rpartition(" ")[2]: v for k, v in attrs.items()})

    def doctype(*_args):
        raise DoctypeRefused()

    parser.StartElementHandler = start
    parser.StartDoctypeDeclHandler = doctype
    parser.Parse(data, True)


# --- extraction: byte-exact, in a file, only what was asked for -----------------------------------------------------------

class Extractor:
    """Writes the resources the caller named (`resource:<row>`, the row number in the resources table) into `extract_to`: each file is
    created exclusively, mode 0600, under a name made of a counter and nothing from the file. A selector that matches nothing is a problem."""

    def __init__(self, ctx, extract_to, selectors):
        self.ctx = ctx
        self.dir = extract_to
        self.selectors = []
        for text in selectors:
            kind, _sep, rest = text.partition(":")
            if kind != "resource" or not rest.isdigit():
                fail("extract: a selector of %d characters is not a selector this tool reads (resource:<row number in the resources table>)" % len(text))
            self.selectors.append({"row": int(rest), "matched": False, "text": text})

    def wants(self, row):
        return any(s["row"] == row for s in self.selectors)

    def write(self, row, label, data, source):
        for sel in self.selectors:
            if sel["row"] == row:
                sel["matched"] = True
        self.ctx.counter[0] += 1
        index = self.ctx.counter[0]
        out = {"locator": "resource row %d" % row, "label": label, "source": source}
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
                self.ctx.problem("resource row %d: the file could not be created in extract_to (%s)" % (row, describe(exc)))
                out["status"] = "failed"
                self.ctx.extracted.append(out)
                return out
        if fd is None:
            self.ctx.problem("resource row %d: ninety-nine files of this name already exist in extract_to" % row)
            out["status"] = "failed"
            self.ctx.extracted.append(out)
            return out
        try:
            with os.fdopen(fd, "wb") as fh:
                fh.write(data)
        except OSError as exc:
            self.ctx.problem("resource row %d: writing failed (%s)" % (row, describe(exc)))
            out["status"] = "failed"
            try:
                os.unlink(target)
            except OSError:
                pass
        else:
            out["status"] = "written"
            out["file"] = shown_path(target)
            out["bytes"] = len(data)
            # No digest of an extracted resource is in the answer: a resource can be a secret, and a hash of a secret confirms it
            # (docs/packs.md section 8). With write_values, in a job, the digest goes to the values file.
            if self.ctx.values.enabled:
                finding = self.ctx.next_finding("E")
                self.ctx.values.add(finding, {"field": "extracted_resource_sha256", "file": out["file"], "bytes": len(data)}, hashlib.sha256(data).hexdigest())
                out["sha256_in_values_file"] = finding
        self.ctx.extracted.append(out)
        return out

    def unmatched(self):
        return [s["text"] for s in self.selectors if not s["matched"]]


# --- the image, with checked access ----------------------------------------------------------------------------------

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


MACHINES = {0x014c: "i386", 0x8664: "x86-64", 0x01c0: "ARM", 0x01c4: "ARMNT", 0xaa64: "ARM64", 0x0200: "IA64", 0x5032: "RISC-V 32", 0x5064: "RISC-V 64"}
DIRS = ["export", "import", "resource", "exception", "certificate", "base_relocation", "debug", "architecture", "global_ptr", "tls", "load_config",
        "bound_import", "iat", "delay_import", "clr_runtime_header", "reserved"]
RES_TYPES = {1: "CURSOR", 2: "BITMAP", 3: "ICON", 4: "MENU", 5: "DIALOG", 6: "STRING", 7: "FONTDIR", 8: "FONT", 9: "ACCELERATOR", 10: "RCDATA",
             11: "MESSAGETABLE", 12: "GROUP_CURSOR", 14: "GROUP_ICON", 16: "VERSION", 17: "DLGINCLUDE", 19: "PLUGPLAY", 20: "VXD", 21: "ANICURSOR",
             22: "ANIICON", 23: "HTML", 24: "MANIFEST"}
DEBUG_TYPES = {1: "COFF", 2: "CODEVIEW", 3: "FPO", 4: "MISC", 5: "EXCEPTION", 6: "FIXUP", 9: "BORLAND", 12: "VC_FEATURE", 13: "POGO", 14: "ILTCG",
               16: "REPRO", 20: "EX_DLLCHARACTERISTICS"}
VERSION_KEYS = ("CompanyName", "FileDescription", "FileVersion", "InternalName", "LegalCopyright", "OriginalFilename", "ProductName", "ProductVersion",
                "LegalTrademarks", "PrivateBuild", "SpecialBuild", "Comments")
FILE_FLAGS = [(0x1, "debug"), (0x2, "prerelease"), (0x4, "patched"), (0x8, "private build"), (0x10, "info inferred"), (0x20, "special build")]
FILE_TYPES = {1: "application", 2: "DLL", 3: "driver", 4: "font", 5: "VxD", 7: "static library"}
COR_FLAGS = [(0x1, "ILONLY"), (0x2, "32BITREQUIRED"), (0x4, "IL_LIBRARY"), (0x8, "STRONGNAMESIGNED"), (0x10, "NATIVE_ENTRYPOINT"), (0x10000, "TRACKDEBUGDATA"), (0x20000, "32BITPREFERRED")]

READ = ["the DOS, COFF and optional headers, the data directory table and the section table (to turn an RVA into a file offset)",
        "the export directory: every function with ordinal, RVA, name and forwarder",
        "the delay-load import descriptors: library names and function names or ordinals",
        "the TLS directory and its callback array",
        "the resource tree: type, name or id, language, RVA, file offset and size of every leaf; the version information; the manifest's requested execution level",
        "the CLR header and the metadata root: runtime version, flags, entry point token, directories, the version string and the stream names and sizes",
        "the debug directory, and the CodeView record's identity and path",
        "the Rich header's decoded entries"]
NOT_READ = ["resource contents beyond the version information and the manifest (unless extract asks for a row)", "the CLR metadata tables, method bodies, and so any assembly name or token's meaning",
            "bound imports, base relocations, exception tables and the load configuration contents",
            "the import directory and the sections (pe_info reads them)", "Authenticode: nothing is parsed or verified", "a strong-name signature: the flag is reported, the signature is not checked",
            "anything about the code: what an export, a callback or an entry point does"]


def when(stamp):
    if not stamp:
        return None
    try:
        return datetime.fromtimestamp(stamp, timezone.utc).isoformat().replace("+00:00", "Z")
    except (OverflowError, OSError, ValueError):
        return None


def parse_headers(img, ctx):
    """The PE headers this tool needs, with an RVA-to-offset mapper. Raises Stop when they are unusable."""
    out = {"format": "PE"}
    if img.size < 0x40:
        raise Stop("failed", "shorter than a DOS header (64 bytes): the file is %d bytes" % img.size, out)
    pe_at, = img.unpack("<I", 0x3C)
    if bytes(img.mm[pe_at:pe_at + 4]) != b"PE\x00\x00":
        raise Stop("failed", "no PE signature where the DOS header points (offset %d of %d)" % (pe_at, img.size), out)
    if pe_at + 24 > img.size:
        raise Stop("failed", "the COFF header runs past the end of the file", out)
    machine, nsec, _stamp, _sym, _nsym, opt_size, _chars = img.unpack("<HHIIIHH", pe_at + 4)
    out["machine"] = MACHINES.get(machine, hex(machine))
    opt_at = pe_at + 24
    avail = max(0, min(opt_size, img.size - opt_at))
    magic = img.unpack("<H", opt_at)[0] if avail >= 2 else None
    if magic not in (0x10b, 0x20b):
        raise Stop("failed", "the optional header magic is %s, neither PE32 (0x10b) nor PE32+ (0x20b)" % ("missing" if magic is None else hex(magic)), out)
    wide = magic == 0x20b
    out["bits"] = 64 if wide else 32
    need = 112 if wide else 96
    if avail < need + 8:
        raise Stop("failed", "the optional header holds %d bytes, too few for its fields and a data directory table" % avail, out)
    image_base = struct.unpack_from("<Q" if wide else "<I", img.mm, opt_at + (24 if wide else 28))[0]
    section_alignment, file_alignment = struct.unpack_from("<II", img.mm, opt_at + 32)
    size_of_headers = struct.unpack_from("<I", img.mm, opt_at + 60)[0]
    out["file_alignment"] = file_alignment
    out["section_alignment"] = section_alignment
    count = struct.unpack_from("<I", img.mm, opt_at + (108 if wide else 92))[0]
    fit = max(0, (avail - need) // 8)
    if min(count, 16) > fit:
        ctx.problem("data directories: %d declared, %d fit inside the optional header the file holds" % (min(count, 16), fit))
    dirs = {}
    for i in range(min(count, 16, fit)):
        rva, size = struct.unpack_from("<II", img.mm, opt_at + need + i * 8)
        if size:
            dirs[DIRS[i]] = (rva, size)
    out["image_base"] = hex(image_base)
    out["directories_declared"] = sorted(dirs)
    table_at = opt_at + opt_size
    maps = []
    sections = []
    unaligned = []
    misaligned = []
    # PE/COFF: FileAlignment "should be a power of 2 between 512 and 64 K, inclusive", and when SectionAlignment is less than the page
    # size the two must be equal (the low-alignment case). Either breach is said; the sections are read as the rule below says.
    power = file_alignment and not file_alignment & (file_alignment - 1)
    alignment_breach = not (power and (0x200 <= file_alignment <= 0x10000 or (file_alignment == section_alignment and section_alignment < 0x1000)))
    if alignment_breach:
        ctx.problem("FileAlignment is 0x%X with SectionAlignment 0x%X: PE/COFF wants a power of 2 from 512 to 64K, or one equal to a SectionAlignment below the "
                    "page size (4096); the section offsets are read as the rule in sections_note says" % (file_alignment, section_alignment))
    for i in range(min(nsec, MAX_SECTIONS)):
        at = table_at + i * 40
        if at + 40 > img.size:
            ctx.problem("section table: %d of %d section headers are in the file" % (i, nsec))
            break
        name = bytes(img.mm[at:at + 8]).rstrip(b"\x00").decode("utf-8", "replace")
        vsize, vaddr, rawsize, rawptr, _a, _b, _c, _d, flags = struct.unpack_from("<IIIIIIHHI", img.mm, at + 8)
        if rawsize and file_alignment and rawptr % file_alignment:
            misaligned.append({"section": text_of(name), "pointer_to_raw_data": rawptr, "file_alignment": file_alignment,
                               "read_from": rawptr & ~0x1FF if rawptr & 0x1FF and file_alignment >= 0x200 else rawptr})
        if rawptr & 0x1FF and file_alignment >= 0x200:
            # PE/COFF: PointerToRawData is a multiple of FileAlignment, and FileAlignment is 512 or more unless SectionAlignment is below
            # the page size (then the two are equal and may be less than 512). With FileAlignment of 512 or more, a value that is not a
            # multiple of 512 breaks that rule: the section is read from the value rounded down to 512, and the header's own value is kept
            # beside it, because readers differ on which of the two they use. With FileAlignment below 512 the value is read as it is.
            unaligned.append({"section": text_of(name), "pointer_to_raw_data": rawptr, "read_from": rawptr & ~0x1FF})
            rawptr &= ~0x1FF
        sections.append((name, vaddr, vsize, rawsize, rawptr, flags))
        if rawsize and rawptr < img.size:
            maps.append((vaddr, min(vsize or rawsize, rawsize), rawptr, min(img.size, rawptr + rawsize), len(maps)))
    if unaligned:
        out["sections_read_from_rounded_offsets"] = unaligned
    if misaligned:
        out["sections_not_a_multiple_of_file_alignment"] = misaligned
        ctx.problem("%d section(s) have a PointerToRawData that is not a multiple of FileAlignment (0x%X), which PE/COFF requires of an executable image: "
                    "see sections_not_a_multiple_of_file_alignment and sections_note" % (len(misaligned), file_alignment))
    if misaligned or unaligned or alignment_breach:
        out["sections_note"] = ("the rule this tool reads sections by: with FileAlignment of 512 or more, a PointerToRawData that is not a multiple of 512 is read from the value "
                                "rounded down to 512 (sections_read_from_rounded_offsets); any other value, a multiple of 512 that is not one of FileAlignment included, "
                                "and every value when FileAlignment is below 512, is read as written. PE/COFF says the value is a multiple of FileAlignment and says nothing "
                                "of rounding: readers differ, and one that reads the other offset reads other bytes. Both values are in the answer")
    if size_of_headers:
        maps.append((0, size_of_headers, 0, min(size_of_headers, img.size), len(maps)))
    by_start = sorted(maps)
    starts = [m[0] for m in by_start]

    def to_range(rva):
        """(file offset, end of the file-backed bytes of the section holding it) or None."""
        i = bisect.bisect_right(starts, rva) - 1
        best = None
        for j in range(i, max(-1, i - OVERLAP_LOOK_BACK), -1):
            vaddr, span, rawptr, file_end, order = by_start[j]
            delta = rva - vaddr
            if 0 <= delta < max(span, 1) and rawptr + delta < file_end and (best is None or order < best[2]):
                best = (rawptr + delta, file_end, order)
        return (best[0], best[1]) if best else None

    def section_of(rva):
        for name, vaddr, vsize, rawsize, rawptr, flags in sections:
            if vaddr <= rva < vaddr + max(vsize, rawsize):
                return name, flags
        return None, 0

    return out, {"wide": wide, "image_base": image_base, "dirs": dirs, "to_range": to_range, "section_of": section_of, "pe_at": pe_at, "sections": sections}


def read_rva_cstr(img, pe, rva, cap=NAME_CAP):
    r = pe["to_range"](rva)
    if r is None:
        return None, False, None
    raw, complete = img.cstr(r[0], r[1], cap)
    return raw, complete, r[0]


# --- exports ---------------------------------------------------------------------------------------------------------------

def read_exports(img, pe, ctx, out):
    rva, size = pe["dirs"]["export"]
    start = pe["to_range"](rva)
    if start is None or start[0] + 40 > start[1]:
        ctx.problem("the export directory (RVA 0x%x) is not backed by file bytes" % rva)
        out["exports"] = {"status": "unreadable"}
        return
    _chars, stamp, _maj, _min, name_rva, base, nfunc, nnames, f_rva, n_rva, o_rva = struct.unpack_from("<IIHHIIIIIII", img.mm, start[0])
    info = {"ordinal_base": base, "functions_declared": nfunc, "names_declared": nnames, "time_date_stamp_raw": stamp, "time_date_stamp_utc": when(stamp)}
    raw, complete, at = read_rva_cstr(img, pe, name_rva)
    if raw is not None:
        info["image_name"] = show(ctx, "export_image_name", raw.decode("utf-8", "replace"), at)
    table = ctx.page("exports")
    if nfunc > MAX_EXPORTS or nnames > MAX_EXPORTS:
        ctx.limit_hit("the export directory declares %d functions and %d names: over the limit of %d, so none were listed" % (nfunc, nnames, MAX_EXPORTS))
        info["status"] = "not_listed"
        out["exports"] = info
        return
    fmap, nmap, omap = pe["to_range"](f_rva), pe["to_range"](n_rva), pe["to_range"](o_rva)
    if nfunc and (fmap is None or fmap[0] + 4 * nfunc > fmap[1]):
        ctx.problem("the export address table (%d entries at RVA 0x%x) is not wholly backed by file bytes" % (nfunc, f_rva))
        nfunc = 0 if fmap is None else max(0, (fmap[1] - fmap[0]) // 4)
    names_for = {}
    if nnames:
        if nmap is None or omap is None or nmap[0] + 4 * nnames > nmap[1] or omap[0] + 2 * nnames > omap[1]:
            ctx.problem("the export name or ordinal table (%d names) is not wholly backed by file bytes: names are listed as far as they are" % nnames)
            nnames = 0 if nmap is None or omap is None else min(nnames, max(0, (nmap[1] - nmap[0]) // 4), max(0, (omap[1] - omap[0]) // 2))
        for j in range(nnames):
            if ctx.expired("the export names"):
                break
            (nrva,) = struct.unpack_from("<I", img.mm, nmap[0] + 4 * j)
            (idx,) = struct.unpack_from("<H", img.mm, omap[0] + 2 * j)
            raw, complete, at = read_rva_cstr(img, pe, nrva)
            if raw is None:
                ctx.problem("export name %d (RVA 0x%x) is not backed by file bytes" % (j, nrva))
                continue
            if not complete:
                ctx.problem("export name %d has no terminator within its section or %d bytes" % (j, NAME_CAP))
            if idx in names_for:
                ctx.problem("exported function index %d is named twice" % idx)
            names_for[idx] = (raw.decode("utf-8", "replace"), at)
    listed = forwarders = unnamed = 0
    for i in range(nfunc):
        if ctx.expired("the export table"):
            break
        (frva,) = struct.unpack_from("<I", img.mm, fmap[0] + 4 * i)
        if frva == 0:
            continue
        row = {"ordinal": base + i, "rva": hex(frva)}
        if rva <= frva < rva + size:
            raw, complete, at = read_rva_cstr(img, pe, frva)
            if raw is not None:
                finding = ctx.next_finding("X")
                row["forwarder"] = show(ctx, "export_forwarder", raw.decode("utf-8", "replace"), at, finding)
                row["finding_id"] = finding
                forwarders += 1
        else:
            section, _flags = pe["section_of"](frva)
            row["section"] = text_of(section) if section is not None else None
        if i in names_for:
            row["name"] = show(ctx, "export_name", names_for[i][0], names_for[i][1])
        else:
            unnamed += 1
        table.add(row)
        listed += 1
    info.update({"functions_listed": listed, "forwarders": forwarders, "listed_by_ordinal_only": unnamed, "table": "exports",
                 "note": "an export is a declaration; a name is a claim (names can be anything the linker was given), and an ordinal-only export has no name here"})
    out["exports"] = info


# --- delay imports ------------------------------------------------------------------------------------------------------------

def read_delay_imports(img, pe, ctx, out):
    """Every delay-load descriptor and its name table. The tables are read once each: a descriptor whose table starts inside one
    already read (two descriptors sharing a table, or overlapping ones) is said and not listed again, a table stops where the next
    one already read begins, and all the descriptors together list at most MAX_DELAY_FUNCTIONS rows, so the table file is bounded
    by the bytes of the file and not by descriptors times entries."""
    rva, size = pe["dirs"]["delay_import"]
    start = pe["to_range"](rva)
    if start is None:
        ctx.problem("the delay-load import directory (RVA 0x%x) is not backed by file bytes" % rva)
        out["delay_imports"] = {"status": "unreadable"}
        return
    wide, base = pe["wide"], pe["image_base"]
    table = ctx.page("delay_imports")
    libs, functions, ordinal_only = [], 0, 0
    walked = []                     # (first file offset, end file offset, descriptor) of each name table read, sorted
    capped = False
    for d in range(MAX_DELAY_DESCRIPTORS + 1):
        at = start[0] + d * 32
        if at + 32 > start[1] or ctx.expired("the delay-load descriptors"):
            if at + 32 > start[1]:
                ctx.problem("the delay-load directory ends inside descriptor %d without a terminating zero descriptor" % d)
            break
        attrs, name_rva, _mod, _iat, int_rva, _bound, _unload, _stamp = struct.unpack_from("<IIIIIIII", img.mm, at)
        if attrs == 0 and name_rva == 0 and int_rva == 0:
            break
        if d == MAX_DELAY_DESCRIPTORS:
            ctx.limit_hit("the delay-load directory holds more than %d descriptors: the first %d are listed" % (MAX_DELAY_DESCRIPTORS, MAX_DELAY_DESCRIPTORS))
            break
        # Attribute bit 0: the fields are RVAs. Without it they are virtual addresses (an old layout).
        va_form = not (attrs & 1)
        fix = (lambda v: v - base) if va_form else (lambda v: v)
        raw, complete, nat = read_rva_cstr(img, pe, fix(name_rva))
        lib = {"index": d, "library": show(ctx, "delay_import_library", raw.decode("utf-8", "replace"), nat) if raw is not None else None, "functions": 0, "address_form": "VA" if va_form else "RVA"}
        if raw is None:
            ctx.problem("delay-load descriptor %d: its library name (0x%x) is not backed by file bytes" % (d, name_rva))
        thunks = pe["to_range"](fix(int_rva)) if int_rva else None
        step = 8 if wide else 4
        if int_rva and thunks is None:
            ctx.problem("delay-load descriptor %d: its name table (0x%x) is not backed by file bytes" % (d, int_rva))
        elif thunks:
            starts = [w[0] for w in walked]
            i = bisect.bisect_right(starts, thunks[0]) - 1
            if i >= 0 and walked[i][0] <= thunks[0] < walked[i][1]:
                lib["name_table_shared_with"] = walked[i][2]
                ctx.problem("delay-load descriptor %d: its name table starts inside the one descriptor %d uses: it is not listed again" % (d, walked[i][2]))
                libs.append(lib)
                continue
            stop_at = starts[i + 1] if i + 1 < len(starts) else thunks[1]
            p = thunks[0]
            k = 0
            while True:
                if p + step > thunks[1]:
                    ctx.problem("delay-load descriptor %d: the name table runs off its section without a terminating zero" % d)
                    break
                if p >= stop_at:
                    lib["name_table_runs_into"] = next(w[2] for w in walked if w[0] == stop_at)
                    ctx.problem("delay-load descriptor %d: its name table runs into the one descriptor %d uses: the rest is not listed again" % (d, lib["name_table_runs_into"]))
                    break
                if functions >= MAX_DELAY_FUNCTIONS:
                    capped = True
                    break
                (entry,) = struct.unpack_from("<Q" if wide else "<I", img.mm, p)
                p += step
                k += 1
                if entry == 0:
                    break
                ordinal_flag = 1 << (63 if wide else 31)
                if entry & ordinal_flag:
                    table.add({"library_index": d, "ordinal": entry & 0xFFFF})
                    ordinal_only += 1
                else:
                    hint_at = pe["to_range"](fix(entry & 0x7FFFFFFF))
                    if hint_at is None:
                        ctx.problem("delay-load descriptor %d: a function name (0x%x) is not backed by file bytes" % (d, entry))
                        continue
                    raw, complete, nat = read_rva_cstr(img, pe, fix(entry & 0x7FFFFFFF) + 2)
                    table.add({"library_index": d, "hint": struct.unpack_from("<H", img.mm, hint_at[0])[0] if hint_at[0] + 2 <= img.size else None,
                               "function": show(ctx, "delay_import_function", raw.decode("utf-8", "replace"), nat) if raw is not None else None})
                functions += 1
                lib["functions"] += 1
                if ctx.expired("the delay-load names"):
                    break
            bisect.insort(walked, (thunks[0], max(p, thunks[0] + 1), d))
        libs.append(lib)
        if capped:
            break
    if capped:
        ctx.limit_hit("the delay-load name tables list more than %d functions together: the first %d are listed" % (MAX_DELAY_FUNCTIONS, MAX_DELAY_FUNCTIONS))
    out["delay_imports"] = {"libraries": libs, "functions_listed": functions, "ordinal_only": ordinal_only, "table": "delay_imports",
                            "note": "a delay-load import names what the loader is asked to resolve on first use, not a call that was made"}


# --- TLS ---------------------------------------------------------------------------------------------------------------------

def read_tls(img, pe, ctx, out):
    rva, size = pe["dirs"]["tls"]
    start = pe["to_range"](rva)
    wide, base = pe["wide"], pe["image_base"]
    need = 40 if wide else 24
    if start is None or start[0] + need > start[1]:
        ctx.problem("the TLS directory (RVA 0x%x) is not backed by file bytes" % rva)
        out["tls"] = {"status": "unreadable"}
        return
    fields = struct.unpack_from("<QQQQII" if wide else "<IIIIII", img.mm, start[0])
    raw_start, raw_end, index_va, callbacks_va, zero_fill, chars = fields
    info = {"start_address_of_raw_data": hex(raw_start), "end_address_of_raw_data": hex(raw_end), "address_of_callbacks": hex(callbacks_va), "size_of_zero_fill": zero_fill}
    callbacks = []
    if callbacks_va:
        r = pe["to_range"](callbacks_va - base) if callbacks_va >= base else None
        step = 8 if wide else 4
        if r is None:
            ctx.problem("the TLS callback array (VA 0x%x) is not backed by file bytes" % callbacks_va)
        else:
            for k in range(MAX_TLS_CALLBACKS + 1):
                if ctx.expired("the TLS callbacks"):
                    break
                p = r[0] + k * step
                if p + step > r[1]:
                    ctx.problem("the TLS callback array runs off its section without a terminating zero")
                    break
                (va,) = struct.unpack_from("<Q" if wide else "<I", img.mm, p)
                if va == 0:
                    break
                if k >= MAX_TLS_CALLBACKS:
                    ctx.limit_hit("the TLS callback array holds more than %d entries: the first %d are listed" % (MAX_TLS_CALLBACKS, MAX_TLS_CALLBACKS))
                    break
                rv = va - base if va >= base else None
                section, flags = pe["section_of"](rv) if rv is not None else (None, 0)
                callbacks.append({"va": hex(va), "rva": hex(rv) if rv is not None else None, "section": text_of(section) if section is not None else None,
                                  "section_is_executable": bool(flags & 0x20000000) if section is not None else None})
    info["callbacks"] = callbacks
    info["note"] = "TLS callbacks are called by the loader before the entry point when the image is loaded; this lists the declaration, not what a callback does"
    out["tls"] = info


# --- resources -----------------------------------------------------------------------------------------------------------------

def utf16_name(img, base, off, limit):
    """A resource name string: a 16-bit length, then that many UTF-16 code units (offset from the start of the resource section)."""
    at = base + off
    if at + 2 > limit:
        return None
    (n,) = struct.unpack_from("<H", img.mm, at)
    if at + 2 + 2 * n > limit:
        return None
    return bytes(img.mm[at + 2:at + 2 + 2 * n]).decode("utf-16-le", "surrogatepass")


def read_resources(img, pe, ctx, out, extractor):
    rva, size = pe["dirs"]["resource"]
    start = pe["to_range"](rva)
    if start is None:
        ctx.problem("the resource directory (RVA 0x%x) is not backed by file bytes" % rva)
        out["resources"] = {"status": "unreadable"}
        return
    root_off, limit = start[0], min(start[1], start[0] + size)
    table = ctx.page("resources")
    leaves, visited, by_type, rows = 0, set(), {}, []
    stack = [(0, [], 0)]
    capped = False
    while stack:
        off, path, depth = stack.pop()
        if ctx.expired("the resource tree"):
            break
        if off in visited:
            ctx.problem("the resource tree reaches the directory at offset 0x%x twice: a loop or a shared directory" % off)
            continue
        visited.add(off)
        at = root_off + off
        if at + 16 > limit:
            ctx.problem("a resource directory at offset 0x%x runs past the resource section's declared size" % off)
            continue
        named, ids = struct.unpack_from("<HH", img.mm, at + 12)
        total = named + ids
        if at + 16 + 8 * total > limit:
            ctx.problem("a resource directory at offset 0x%x declares %d entries and the section holds fewer" % (off, total))
            total = max(0, (limit - at - 16) // 8)
        children = []
        for k in range(total):
            if ctx.expired("the resource tree"):
                break
            name_or_id, target = struct.unpack_from("<II", img.mm, at + 16 + 8 * k)
            if name_or_id & 0x80000000:
                nm = utf16_name(img, root_off, name_or_id & 0x7FFFFFFF, limit)
                label = shown_at(ctx, nm, root_off + (name_or_id & 0x7FFFFFFF) + 2, True) if nm is not None else None
                label = label if label is not None else "?"
            else:
                label = name_or_id
            if target & 0x80000000:
                if depth >= 2:
                    ctx.problem("the resource tree is deeper than type / name / language at offset 0x%x" % off)
                    continue
                children.append((target & 0x7FFFFFFF, path + [label], depth + 1))
            else:
                if len(rows) >= MAX_RESOURCES:
                    capped = True
                    continue
                dat = root_off + target
                if dat + 16 > limit:
                    ctx.problem("a resource data entry at offset 0x%x lies outside the resource section" % target)
                    continue
                data_rva, dsize, codepage, _res = struct.unpack_from("<IIII", img.mm, dat)
                r = pe["to_range"](data_rva)
                tname = RES_TYPES.get(path[0]) if path and isinstance(path[0], int) else (path[0] if path else None)
                row = {"row": len(rows), "type": tname if tname is not None else (path[0] if path else None), "name": path[1] if len(path) > 1 else None,
                       "language": label, "rva": hex(data_rva), "size": dsize, "code_page": codepage,
                       "file_offset": r[0] if r else None, "in_file": bool(r and r[0] + dsize <= r[1])}
                if r is None:
                    ctx.problem("resource row %d: its data (RVA 0x%x) is not backed by file bytes" % (len(rows), data_rva))
                elif not row["in_file"]:
                    ctx.problem("resource row %d: its %d bytes run past the bytes the file holds" % (len(rows), dsize))
                rows.append(row)
                key = str(row["type"])
                by_type[key] = by_type.get(key, 0) + 1
                table.add(row)
                leaves += 1
        stack.extend(reversed(children))
    if capped:
        ctx.limit_hit("the resource tree holds more than %d leaves: the first %d are listed" % (MAX_RESOURCES, MAX_RESOURCES))
    out["resources"] = {"leaves": leaves, "by_type": by_type, "table": "resources"}
    # Version information and the manifest are read; everything else only when extract asks.
    for row in rows:
        if not row["in_file"]:
            continue
        if row["type"] == "VERSION" and "version_info" not in out["resources"]:
            out["resources"]["version_info"] = read_version(img, row, ctx)
        elif row["type"] == "MANIFEST" and "manifest" not in out["resources"]:
            out["resources"]["manifest"] = read_manifest(img, row, ctx)
        if extractor is not None and extractor.wants(row["row"]):
            if row["size"] > ctx.cfg["max_stream_bytes"]:
                ctx.limit_hit("resource row %d: %d bytes is over max_stream_bytes (%d): not extracted" % (row["row"], row["size"], ctx.cfg["max_stream_bytes"]))
                continue
            try:
                ctx.spend(row["size"], "resource row %d" % row["row"])
            except Over as exc:
                ctx.limit_hit(str(exc))
                continue
            extractor.write(row["row"], "%s" % row["type"], bytes(img.mm[row["file_offset"]:row["file_offset"] + row["size"]]), "resource data, byte for byte")
    if extractor is not None:
        for sel in extractor.selectors:
            if sel["row"] >= len(rows):
                ctx.problem("extract %s: the resources table has %d rows" % (sel["text"], len(rows)))
                sel["matched"] = True


def read_version(img, row, ctx):
    """VS_VERSIONINFO: the fixed file information, then the StringFileInfo string tables."""
    size = min(row["size"], ctx.cfg["max_stream_bytes"])
    data = bytes(img.mm[row["file_offset"]:row["file_offset"] + size])
    info = {"status": "read"}
    if row["size"] > size:
        info["status"] = "partial"
        ctx.limit_hit("resource row %d: the version resource is %d bytes, over max_stream_bytes (%d): its first %d bytes were read" % (row["row"], row["size"], size, size))

    keys_at = {}                    # a key's file offset, for shown_at

    def broken(where, at):
        info["status"] = "partial"
        ctx.problem("resource row %d: a version block in %s at offset %d has a length that does not fit (under 6 bytes, or past its parent): the rest of it was not read" % (row["row"], where, at))

    def block(pos, end):
        """(key, value_length, type, value_start, children_start, next_pos) of the block at pos."""
        if pos + 6 > end:
            return None
        length, vlen, typ = struct.unpack_from("<HHH", data, pos)
        if length < 6 or pos + length > end:
            return None
        k = pos + 6
        key_end = k
        while key_end + 2 <= pos + length and data[key_end:key_end + 2] != b"\x00\x00":
            key_end += 2
        key = data[k:key_end].decode("utf-16-le", "replace")
        val = (key_end + 2 + 3) & ~3
        keys_at[key] = row["file_offset"] + k
        return key, vlen, typ, val, pos + length

    top = block(0, len(data))
    if top is None or top[0] != "VS_VERSION_INFO":
        info["status"] = "not a VS_VERSIONINFO block"
        ctx.problem("resource row %d: the version resource does not begin with a VS_VERSION_INFO block" % row["row"])
        return info
    key, vlen, typ, val, end = top
    if vlen >= 52 and val + 52 <= end:
        sig, _sv, fvms, fvls, pvms, pvls, _mask, flags, _os, ftype, _sub, _d1, _d2 = struct.unpack_from("<IIIIIIIIIIIII", data, val)
        if sig == 0xFEEF04BD:
            info["fixed"] = {"file_version": "%d.%d.%d.%d" % (fvms >> 16, fvms & 0xFFFF, fvls >> 16, fvls & 0xFFFF),
                             "product_version": "%d.%d.%d.%d" % (pvms >> 16, pvms & 0xFFFF, pvls >> 16, pvls & 0xFFFF),
                             "file_flags": [n for bit, n in FILE_FLAGS if flags & bit], "file_type": FILE_TYPES.get(ftype, "type %d" % ftype)}
        else:
            ctx.problem("resource row %d: the fixed file information signature is 0x%08X, not 0xFEEF04BD" % (row["row"], sig))
        val += (vlen + 3) & ~3
    strings, other = {}, []
    pos = val
    guard = 0
    while pos < end:
        if guard >= 64:
            info["status"] = "partial"
            ctx.limit_hit("resource row %d: the version information holds more than 64 top-level blocks: the first 64 were read" % row["row"])
            break
        guard += 1
        b = block(pos, end)
        if b is None:
            if end - pos >= 6 and any(data[pos:end]):
                broken("VS_VERSION_INFO", pos)
            break
        bkey, _bv, _bt, bval, bend = b
        if bkey == "StringFileInfo":
            tpos = bval
            while tpos < bend:
                t = block(tpos, bend)
                if t is None:
                    if bend - tpos >= 6 and any(data[tpos:bend]):
                        broken("StringFileInfo", tpos)
                    break
                tkey, _tv, _tt, tval, tend = t
                table = {}
                spos, count = tval, 0
                while spos < tend:
                    if ctx.expired("the version strings"):
                        break
                    if count >= MAX_VERSION_STRINGS:
                        info["status"] = "partial"
                        ctx.limit_hit("resource row %d: a version string table holds more than %d strings: the first %d were read" % (row["row"], MAX_VERSION_STRINGS, MAX_VERSION_STRINGS))
                        break
                    count += 1
                    s = block(spos, tend)
                    if s is None:
                        if tend - spos >= 6 and any(data[spos:tend]):
                            broken("a StringTable", spos)
                        break
                    skey, svlen, _st, sval, send = s
                    raw = data[sval:min(send, sval + 2 * svlen)] if svlen else b""
                    value = raw.decode("utf-16-le", "replace").rstrip("\x00")
                    if skey in VERSION_KEYS:
                        finding = ctx.next_finding("V")
                        ctx.values.add(finding, {"field": "version_string", "key": skey}, value)
                        name, n = skey, 1
                        while name in table:
                            n += 1
                            name = "%s #%d" % (skey, n)
                        table[name] = {"value": text_of(value, "names") if len(value) <= 256 else None, "length": len(value), "finding_id": finding}
                    else:
                        other.append(shown_at(ctx, skey, keys_at.get(skey), True))
                    spos = send if send > spos else spos + 6
                    spos = (spos + 3) & ~3
                # The key is the file's own text: it is withheld as a string at its offset is (shown_at), and two tables of one key are both kept.
                shown_key_text = shown_at(ctx, tkey, keys_at.get(tkey), True)
                name, n = shown_key_text, 1
                while name in strings:
                    n += 1
                    name = "%s #%d" % (shown_key_text, n)
                strings[name] = table
                tpos = (tend + 3) & ~3
        pos = (bend + 3) & ~3
    info["string_tables"] = strings
    info["other_keys"] = other[:50]
    if len(other) > 50:
        info["other_keys_total"] = len(other)
        ctx.limit_hit("resource row %d: the version string tables hold %d keys beyond the well-known ones: the first 50 are named" % (row["row"], len(other)))
    info["note"] = "version strings are claims the file makes about itself: an editable company name, original file name and version are not evidence of origin"
    return info


def read_manifest(img, row, ctx):
    size = row["size"]
    if size > 1 << 20:
        ctx.limit_hit("resource row %d: the manifest is %d bytes, over the 1 MiB read limit" % (row["row"], size))
        return {"status": "not_read", "bytes": size}
    data = bytes(img.mm[row["file_offset"]:row["file_offset"] + size])
    if data[:3] == b"\xef\xbb\xbf":
        data = data[3:]
    info = {"status": "read", "bytes": size, "requested_execution_levels": []}

    def element(local, attrs):
        if local == "requestedExecutionLevel" and len(info["requested_execution_levels"]) < 8:
            info["requested_execution_levels"].append({"level": text_of(attrs.get("level", ""), "names"), "uiAccess": text_of(attrs.get("uiAccess", ""), "names") or None})

    try:
        xml_elements(data, element)
    except DoctypeRefused:
        info["status"] = "doctype_refused"
        ctx.problem("resource row %d: the manifest contains a DOCTYPE, which is refused: it was not parsed" % row["row"])
    except xml.parsers.expat.ExpatError as exc:
        info["status"] = "not_well_formed"
        ctx.problem("resource row %d: the manifest is not well-formed XML (%s)" % (row["row"], xml.parsers.expat.ErrorString(exc.code)))
    except (LookupError, ValueError) as exc:
        info["status"] = "encoding_not_readable"
        ctx.problem("resource row %d: the manifest declares an encoding the XML reader cannot decode (%s): it was not parsed" % (row["row"], type(exc).__name__))
    return info


# --- CLR ----------------------------------------------------------------------------------------------------------------------

def read_clr(img, pe, ctx, out):
    rva, size = pe["dirs"]["clr_runtime_header"]
    start = pe["to_range"](rva)
    if start is None or start[0] + 72 > start[1]:
        ctx.problem("the CLR header (RVA 0x%x) is not backed by file bytes" % rva)
        out["clr"] = {"status": "unreadable"}
        return
    cb, major, minor, md_rva, md_size, flags, entry, res_rva, res_size, sn_rva, sn_size = struct.unpack_from("<IHHIIIIIIII", img.mm, start[0])
    mn_rva, mn_size = struct.unpack_from("<II", img.mm, start[0] + 64)
    info = {"header_size": cb, "runtime_version": "%d.%d" % (major, minor), "flags": [n for bit, n in COR_FLAGS if flags & bit], "flags_raw": hex(flags),
            "entry_point": {"value": hex(entry), "is_native_rva": bool(flags & 0x10)},
            "strong_name_signature_field": {"rva": hex(sn_rva), "size": sn_size, "present": bool(sn_size)},
            "managed_native_header": {"rva": hex(mn_rva), "size": mn_size, "present": bool(mn_size)}}
    if not (flags & 0x10) and entry:
        info["entry_point"]["token_table"] = "0x%02X" % (entry >> 24)
        info["entry_point"]["token_row"] = entry & 0xFFFFFF
    if mn_size:
        r = pe["to_range"](mn_rva)
        if r is not None and r[0] + 4 <= r[1]:
            info["managed_native_header"]["first_four_bytes"] = bytes(img.mm[r[0]:r[0] + 4]).hex()
    info["notes"] = ["a strong-name signature field is a declaration of a signature, not a verified one, and not the publisher's trust",
                     "a managed-native header is native-code metadata that is present alongside the IL; what it holds is named by the runtime's own documentation, not here",
                     "the metadata tables are not read: this answer has no assembly name, version, type or method"]
    md = pe["to_range"](md_rva) if md_rva else None
    if md is None:
        ctx.problem("the CLR metadata root (RVA 0x%x) is not backed by file bytes" % md_rva)
        info["metadata"] = {"status": "unreadable"}
        out["clr"] = info
        return
    end = min(md[1], md[0] + md_size) if md_size else md[1]
    if md[0] + 16 > end:
        ctx.problem("the CLR metadata root is shorter than its fixed fields")
        info["metadata"] = {"status": "unreadable"}
        out["clr"] = info
        return
    sig, mj, mn, _res, vlen = struct.unpack_from("<IHHII", img.mm, md[0])
    meta = {"signature": "0x%08X" % sig, "signature_ok": sig == 0x424A5342, "format_version": "%d.%d" % (mj, mn)}
    if sig != 0x424A5342:
        ctx.problem("the CLR metadata root does not begin with the BSJB signature (0x424A5342)")
        info["metadata"] = meta
        out["clr"] = info
        return
    if vlen > 255 or md[0] + 16 + vlen + 4 > end:
        ctx.problem("the CLR metadata version string declares %d bytes, more than the root holds" % vlen)
        info["metadata"] = meta
        out["clr"] = info
        return
    ver = bytes(img.mm[md[0] + 16:md[0] + 16 + vlen]).split(b"\x00")[0].decode("utf-8", "replace")
    meta["version_string"] = shown_at(ctx, ver, md[0] + 16)
    p = md[0] + 16 + vlen
    _flags, nstreams = struct.unpack_from("<HH", img.mm, p)
    p += 4
    streams = []
    if nstreams > MAX_STREAM_HEADERS:
        ctx.limit_hit("the CLR metadata declares %d stream headers: the first %d are read" % (nstreams, MAX_STREAM_HEADERS))
    for i in range(min(nstreams, MAX_STREAM_HEADERS)):
        if p + 9 > end:
            ctx.problem("the CLR metadata declares %d stream headers and the root holds %d" % (nstreams, i))
            break
        off, ssize = struct.unpack_from("<II", img.mm, p)
        q = p + 8
        nul = img.mm.find(b"\x00", q, min(end, q + 32))
        if nul < 0:
            ctx.problem("a CLR metadata stream name has no terminator")
            break
        name = bytes(img.mm[q:nul]).decode("ascii", "replace")
        streams.append({"name": shown_at(ctx, name, q), "offset": off, "size": ssize, "within_root": off + ssize <= (md_size or end - md[0])})
        p = q + ((nul - q + 1 + 3) & ~3)
    meta["streams"] = streams
    meta["streams_declared"] = nstreams
    info["metadata"] = meta
    out["clr"] = info


# --- debug --------------------------------------------------------------------------------------------------------------------

def read_debug(img, pe, ctx, out):
    rva, size = pe["dirs"]["debug"]
    start = pe["to_range"](rva)
    if start is None:
        ctx.problem("the debug directory (RVA 0x%x) is not backed by file bytes" % rva)
        out["debug"] = {"status": "unreadable"}
        return
    count = min(size // 28, MAX_DEBUG_ENTRIES)
    if size // 28 > MAX_DEBUG_ENTRIES:
        ctx.limit_hit("the debug directory declares %d entries: the first %d are read" % (size // 28, MAX_DEBUG_ENTRIES))
    if size % 28:
        ctx.problem("the debug directory size (%d) is not a whole number of 28-byte entries" % size)
    entries = []
    for i in range(count):
        if ctx.expired("the debug directory"):
            break
        at = start[0] + i * 28
        if at + 28 > start[1]:
            ctx.problem("debug entry %d runs past its section" % i)
            break
        _c, stamp, mj, mn, typ, dsize, data_rva, ptr = struct.unpack_from("<IIHHIIII", img.mm, at)
        row = {"type": DEBUG_TYPES.get(typ, "type %d" % typ), "type_raw": typ, "time_date_stamp_raw": stamp, "time_date_stamp_utc": when(stamp), "size": dsize,
               "pointer_to_raw_data": ptr}
        if typ == 2 and ptr and ptr + 24 <= img.size and dsize >= 24:
            sig = bytes(img.mm[ptr:ptr + 4])
            if sig == b"RSDS":
                g = bytes(img.mm[ptr + 4:ptr + 20])
                age, = struct.unpack_from("<I", img.mm, ptr + 20)
                raw, complete = img.cstr(ptr + 24, min(img.size, ptr + dsize), NAME_CAP)
                d1, d2, d3 = struct.unpack_from("<IHH", g)
                # Sixteen bytes that hold a run of nine or more token characters are text placed where the GUID goes, and their hex would print
                # the text: such a field is given as withheld (for random bytes, about one in twenty-five thousand).
                shown_guid = ("<16 bytes that read as text, withheld>" if guid_is_text(g) else
                              made("%08X-%04X-%04X-%s-%s" % (d1, d2, d3, g[8:10].hex().upper(), g[10:16].hex().upper())))
                row["codeview"] = {"signature": "RSDS", "guid": shown_guid, "age": age}
                if raw is not None:
                    finding = ctx.next_finding("D")
                    path_text = raw.decode("utf-8", "replace")
                    row["codeview"]["pdb_path"] = show(ctx, "pdb_path", path_text, ptr + 24, finding)
                    row["codeview"]["pdb_path_length"] = len(raw)
                    row["codeview"]["finding_id"] = finding
                    row["codeview"]["note"] = "a path the build wrote: a claim about the build machine, not evidence of where the file was made or by whom"
            else:
                row["codeview"] = {"signature": sig.hex(), "note": "a CodeView record this tool does not read (it reads RSDS)"}
        entries.append(row)
    out["debug"] = {"entries": entries}
    if any(e["type_raw"] == 16 for e in entries):
        # A REPRO entry says the build is reproducible: the linker writes a hash of the build into the time stamps, so none of
        # them is a time (the COFF header's, the export directory's, each debug entry's).
        for e in entries:
            e["time_date_stamp_utc"] = None
            e["time_date_stamp_note"] = "not a time: a REPRO entry is present, and the stamp is a hash of the build"
        out["debug"]["repro"] = True
        out["debug"]["note"] = "a REPRO debug entry is present: the time stamps of this file are build hashes, not times"
        if isinstance(out.get("exports"), dict) and "time_date_stamp_utc" in out["exports"]:
            out["exports"]["time_date_stamp_utc"] = None
            out["exports"]["time_date_stamp_note"] = "not a time: a REPRO entry is present, and the stamp is a hash of the build"


# --- Rich header --------------------------------------------------------------------------------------------------------------

def read_rich(img, pe, ctx, out):
    """The Rich header sits between the DOS stub and the PE header: 'DanS' ^ key, three zero words ^ key, (comp_id, count) pairs ^ key, 'Rich', key."""
    limit = min(pe["pe_at"], 0x1000, img.size)
    region = bytes(img.mm[0x80:limit]) if limit > 0x80 else b""
    at = region.rfind(b"Rich")
    if at < 0 or at + 8 > len(region):
        return
    key = struct.unpack_from("<I", region, at + 4)[0]
    words = [struct.unpack_from("<I", region, o)[0] ^ key for o in range(0, at - at % 4, 4)]
    try:
        start = max(i for i, w in enumerate(words) if w == 0x536E6144)
    except ValueError:
        out["rich_header"] = {"status": "a 'Rich' marker with no 'DanS' start before it", "key": hex(key)}
        ctx.problem("a Rich marker was found with no DanS start before it: the Rich header is not read")
        return
    if any(w != 0 for w in words[start + 1:start + 4]):
        out["rich_header"] = {"status": "the three padding words after DanS do not decode to zero with the stored key", "key": hex(key)}
        ctx.problem("the Rich header's padding does not decode to zero with its stored key: the entries are not read")
        return
    body = words[start + 4:]
    if len(body) % 2:
        ctx.problem("the Rich header holds an odd number of words after its padding")
        body = body[:-1]
    entries = [{"product_id": body[i] >> 16, "build": body[i] & 0xFFFF, "count": body[i + 1]} for i in range(0, len(body), 2)]
    if len(entries) > 512:
        ctx.limit_hit("the Rich header holds %d entries: the first 512 are listed" % len(entries))
        entries = entries[:512]
    out["rich_header"] = {"status": "decoded", "key": hex(key), "offset": 0x80 + start * 4, "entries": entries,
                          "note": "raw numbers from the header, decoded with the stored key; not validated, and not mapped to a product or a compiler here. A toolchain lead, not a clock"}


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
    try:
        args = json.load(sys.stdin)
    except ValueError as exc:
        fail("arguments are not valid JSON", reason=str(exc))
    if not isinstance(args, dict):
        fail("arguments must be a JSON object")
    path = args.get("path")
    if not isinstance(path, str) or not path:
        fail("path is required: a PE file to read the directories of")
    why_not = file_problem(path)
    if why_not:
        fail(why_not, path=path)
    extract_to = args.get("extract_to")
    if extract_to is not None and (not isinstance(extract_to, str) or not extract_to):
        fail("extract_to must be a non-empty path when supplied")
    selectors = args.get("extract", [])
    if not isinstance(selectors, list) or not all(isinstance(x, str) and x for x in selectors) or len(selectors) > MAX_EXTRACT:
        fail("extract must be a list of at most %d selectors (resource:<row number in the resources table>)" % MAX_EXTRACT)
    if selectors and extract_to is None:
        fail("extract names resources to write and needs extract_to: a directory under work/<your agent id>/ (in a job, under $OUT)")
    if extract_to is not None:
        extract_to = resolve_output(extract_to, "extract_to")
        try:
            os.makedirs(extract_to, exist_ok=True)
        except OSError as exc:
            fail("extract_to could not be created: %s" % describe(exc))
    write_values = args.get("write_values", False)
    if not isinstance(write_values, bool):
        fail("write_values must be true or false")
    cfg = {"max_stream_bytes": positive_int(args, "max_stream_bytes", DEFAULT_STREAM), "max_total_bytes": positive_int(args, "max_total_bytes", DEFAULT_TOTAL),
           "limit": positive_int(args, "limit", DEFAULT_LIMIT, MAX_LIMIT)}
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
    if size == 0:
        values.close()
        fail("the file is empty", path=path)
    extractor = Extractor(ctx, extract_to, selectors) if selectors else None
    body, stop = {}, None
    try:
        with open(path, "rb") as fh:
            mm = mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_READ)
            try:
                img = Image(mm)
                ctx.img = img
                if img.mm[:2] != b"MZ":
                    values.close()
                    fail("this is not a PE file (no MZ header)", status="unsupported", path=path, head_hex=bytes(img.mm[:4]).hex())
                try:
                    body, pe = parse_headers(img, ctx)
                except Stop as exc:
                    stop = exc
                    body = exc.partial
                except Short as exc:
                    stop = Stop("failed", "the headers run past the end of the file: %s" % exc)
                if stop is None:
                    d = pe["dirs"]
                    if "export" in d:
                        guarded(ctx, "exports", read_exports, img, pe, ctx, body)
                    if "delay_import" in d:
                        guarded(ctx, "delay imports", read_delay_imports, img, pe, ctx, body)
                    if "tls" in d:
                        guarded(ctx, "TLS", read_tls, img, pe, ctx, body)
                    if "resource" in d:
                        guarded(ctx, "resources", read_resources, img, pe, ctx, body, extractor)
                    elif extractor is not None:
                        ctx.problem("extract: no resource directory is declared")
                    if "clr_runtime_header" in d:
                        guarded(ctx, "CLR header", read_clr, img, pe, ctx, body)
                    if "debug" in d:
                        guarded(ctx, "debug directory", read_debug, img, pe, ctx, body)
                    guarded(ctx, "Rich header", read_rich, img, pe, ctx, body)
                    body["coverage"] = {"structures_read": READ, "structures_not_read": NOT_READ}
            finally:
                ctx.img = None
                mm.close()
    finally:
        values.close()
        ctx.names.close()

    if extractor is not None:
        for text in extractor.unmatched():
            ctx.problem("extract %s matched nothing" % text_of(text, "names"))
    tables = {}
    for name, page in ctx.pages.items():
        tables[name] = page.finish()
        tables[name]["rows"] = page.page
        if page.not_written:
            ctx.problem("the whole %s table could not be written to a file: %s" % (name, page.not_written))
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
    basis = ("every directory this tool reads and the file declares was read in full" if status == "complete" else
             "%d problem(s), %d limit(s): see `problems`, `limits_hit` and `coverage`" % (len(ctx.problems), len(ctx.limits)))
    result = {**head_out, **body, "status": status, "status_basis": basis, "problems": ctx.problems, "limits_hit": ctx.limits, "tables": tables, "truncated": truncated,
              "withheld": COUNTS, "secret_values": values.summary(), "note": NOTE}
    if extractor is not None:
        result["extracted"] = ctx.extracted
        result["extraction_note"] = "Resources are written byte for byte, mode 0600, and can contain secrets: run extraction in a job with secret_output: true."
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
