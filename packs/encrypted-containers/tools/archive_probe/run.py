#!/usr/bin/env python3
"""Say what an archive or document shows about its own protection, and what it does not.

The question people ask is "can we open it". The question that decides an
exfiltration case is a different one: are the member names readable without a
password. They are two findings, and this tool reports both where it can.

What it establishes, and how:

    ZIP      structurally: the End Of Central Directory record (and the Zip64 record
             before its locator, wherever a locator is) and each central directory
             entry, read by this tool from the bytes. Per member: the encryption
             flag, the scheme (the AES extra field is parsed: strength and AE
             version), the DOS time with its raw words (no zone) and an extended
             timestamp where one is recorded. A name that is not valid text does not
             hide the other members: it is shown with the bytes escaped. Empty and
             self-extracting archives are read too: the container is found from its
             end, not from byte zero.
    7-Zip    through the installed 7z (a bounded run, no password prompt) when
             there is one: the member list, each member's encryption flag, and
             whether the header is encrypted. The start header is read
             structurally either way (its CRCs are checked); a byte search for the
             AES coder id is kept as a hint when 7z is absent or cannot read it.
    RAR      identified. Its protection is not determined here.
    PDF, OLE compound file (Office)
             markers only, found by a byte search, reported as a heuristic: where
             the marker is, never a verdict. A marker in the file does not say
             which revision of the document it belongs to, and no marker does not
             say the document is not encrypted (binary Office files record their
             encryption inside the document stream, not in a stream with a name).
             The structural reader for these is not provided by this pack.

Evidence is hostile input: nothing is extracted or executed, only metadata is read,
and what is read is bounded (`max_metadata_bytes`, whatever the file's own headers
declare); a result that is cut says so. The tool has its own clock (`max_seconds`,
below the manifest's timeout) and stops on SIGTERM, SIGINT and SIGHUP with one JSON
answer and the exit status 128 + the signal; the 7z it started is ended with it.
Names, paths and header strings are printed through the SHARED NAMES block below: a
part shaped like an identifier or a secret is withheld (by shape; see the block).
"""
import heapq
import json
import mmap
import os
import re
import shutil
import struct
import subprocess
import sys
import threading
import zlib
from datetime import datetime, timedelta, timezone

PARSER = "archive_probe/3"


# Lossless paging (the same in every library tool that pages): the page an
# agent reads stays small, and when there are more rows the whole result is
# written as JSON Lines under work/<agent>/tool-output and named.
import hashlib
import signal
import tempfile
from pathlib import Path




class LosslessPage:
    def __init__(self, tool: str, key: object, limit: int):
        if isinstance(limit, bool) or not isinstance(limit, int) or limit < 1:
            raise ValueError("limit must be a positive integer")
        self.tool = re.sub(r"[^A-Za-z0-9_.-]", "_", tool)
        self.limit = limit
        self.page: list[object] = []
        self.total = 0
        self._out = None
        self._tmp: Path | None = None
        digest = hashlib.sha256(
            json.dumps(key, sort_keys=True, default=str).encode("utf-8")
        ).hexdigest()[:16]
        name = f"{self.tool}-{digest}.jsonl"
        job, out = os.environ.get("JOB_ID"), os.environ.get("OUT")
        if job and out:
            # In a job only $OUT is written, and it is sealed as the job's
            # output: the whole result is cited from there.
            self.path = Path(out) / "tool-output" / name
            self.shown = "store/jobs/%s/out/tool-output/%s" % (re.sub(r"[^A-Za-z0-9_.-]", "_", job), name)
        else:
            agent = re.sub(
                r"[^A-Za-z0-9_.-]", "_", os.environ.get("AGENT_ID") or "tool"
            )
            self.path = Path("work") / agent / "tool-output" / name
            self.shown = str(self.path)

    def _cannot_write(self, exc: BaseException) -> None:
        """The whole result cannot be kept: say so as JSON and stop, never a traceback."""
        import sys as _sys
        _sys.stdout.write(json.dumps({
            "error": "the whole result (%d rows so far) cannot be written to %s: %s. Outside a job the place is your own "
                     "work/<your id>/ directory; in a job it is $OUT." % (self.total, self.shown, exc),
            "status": "failed",
            "status_basis": "the whole result could not be written, so the tool stopped with an error and returned no result",
        }) + "\n")
        _sys.exit(1)

    def _write(self, row: object) -> None:
        assert self._out is not None
        text = json.dumps(row, ensure_ascii=False, default=str)
        try:
            text.encode("utf-8")
        except UnicodeEncodeError:
            # A lone surrogate (a file name that is not UTF-8): escape it, lose nothing.
            text = json.dumps(row, ensure_ascii=True, default=str)
        try:
            self._out.write(text)
            self._out.write("\n")
        except OSError as exc:
            self._cannot_write(exc)

    def add(self, row: object) -> None:
        self.total += 1
        if len(self.page) < self.limit:
            self.page.append(row)
            return
        if self._out is None:
            try:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                fd, name = tempfile.mkstemp(
                    dir=self.path.parent, prefix=f".{self.path.name}-"
                )
                self._tmp = Path(name)
                self._out = os.fdopen(fd, "w", encoding="utf-8")
            except OSError as exc:
                self._cannot_write(exc)
            for kept in self.page:
                self._write(kept)
        self._write(row)

    def finish(self) -> dict:
        result = {
            "matched": self.total,
            "returned": len(self.page),
            "truncated": self.total > len(self.page),
        }
        if self._out is not None:
            try:
                self._out.flush()
                os.fsync(self._out.fileno())
                self._out.close()
                assert self._tmp is not None
                os.replace(self._tmp, self.path)
            except OSError as exc:
                self._cannot_write(exc)
            result["all_results"] = self.shown
            result["all_results_format"] = "JSON Lines, one complete result per line"
        return result


# BEGIN SHARED PLACE
# The same text is in every windows-forensics tool that keeps a result file (a windows-forensics test holds the copies equal).
# A result file that is there is never replaced by another result: a file of the same bytes is named again, any other result takes the next free
# <stem>-<n><suffix>. The name is taken first, with an exclusive create, so a result written at the same moment cannot be replaced either.
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
    """Move the finished `tmp` to `path` and never replace what is there. The name is taken first, with an exclusive create, so a
    result written at the same moment cannot be replaced either. Returns the path that holds it."""
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
    raise OSError("no free name beside %s" % path)
# END SHARED PLACE


# BEGIN SHARED PAGE
# The same text is in every windows-forensics tool that pages through LosslessPage (held equal by a windows-forensics test): LosslessPage replaces a file of the
# same name; this one places its finished file with place_without_replacing, and registers itself so that a stop can remove its temporary file.
PAGES = []


class NoReplacePage(LosslessPage):
    """LosslessPage whose finished file is placed without replacing an earlier file of the same name (a rerun with other limits, or one
    the time limit stopped, must not leave a smaller file where a larger one was)."""

    def __init__(self, tool, key, limit):
        super().__init__(tool, key, limit)
        PAGES.append(self)

    def finish(self) -> dict:
        result = {"matched": self.total, "returned": len(self.page), "truncated": self.total > len(self.page)}
        if self._out is not None:
            try:
                self._out.flush()
                os.fsync(self._out.fileno())
                self._out.close()
                assert self._tmp is not None
                placed = place_without_replacing(self._tmp, self.path)
            except OSError as exc:
                self._cannot_write(exc)
            self._tmp = None
            self.path = placed
            self.shown = self.shown[: len(self.shown) - len(Path(self.shown).name)] + placed.name
            result["all_results"] = self.shown
            result["all_results_format"] = "JSON Lines, one complete result per line"
        return result
# END SHARED PAGE


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


# BEGIN SHARED NAMES
# The same text is in recovery_key_scan, archive_probe and crypto_id (a pack test holds the copies equal). It decides what a name,
# a path, a header string or a diagnostic from evidence may show. Layer 1 (shown, withhold) cuts out of a string the spans that are
# shaped like an identifier or a secret and puts a fixed placeholder where each was (no length, no fragment); layer 2 (seal) reads
# every string of what is about to be printed or paged once more, by rules of its own, and replaces a string the first layer let
# through that still looks like a secret.
#
# WITHHELD, by shape: a recovery password (eight groups of six digits, joined by none to three characters that are not letters or digits)
# in a path component, whole component, and across the components of a path (the separators of a path join its groups); a run of 10 or
# more digits; a run of 8 or more letters and digits that has a digit in it (System32 and a few such names of Windows are let through); a
# letters-only run of 8 or more that is not one word, a camel-case word or all capitals; groups of 4 to 6 characters joined by one `-`, `_`
# or `.` (3 or more digit-only groups, or 4 or more groups that each hold a digit or are all capitals), and four or more groups of exactly
# six digits joined by spaces; the value after password, secret, token, api key, credential, auth (`password=...`); user-info; and the
# token shapes of the shared WITHHOLDING block above (vendor prefixes, JWT, long hex, long mixed runs, base64 with `/`). A string is also
# judged after NFKC, with invisible characters taken out and with the Cyrillic and Greek letters that look like Latin ones read as Latin,
# and a hit there that the string as written does not show withholds the whole string.
# NOT WITHHELD, by design: an identifier of 7 characters or fewer, a lowercase-only random run (it reads as a word), a secret that does
# not look like one, an all-capital letters-only run of any length, groups of other sizes (three groups of 4 to 6 letters and digits are
# printed), a recovery password cut into pieces by anything else than the separators above, and anything in the data a tool reads rather
# than prints.
# BOUNDED: the token rule of the WITHHOLDING block re-reads the text in front of a `/` once for each flagged piece after it, so its time
# grows with the square of a long run of name characters. What that block is given is therefore bounded first (_unjudgeable): a string of
# more than MAX_JUDGED characters, as written or after NFKC, or one that holds a `/` and a run of name characters of more than MAX_RUN, is
# withheld whole and not judged. The block itself is repaired at its source in a change of its own, for every pack that copies it.
# Measured on random draws and on real directory trees: tests/pack-encrypted-containers-names.test.ts and the manifests give the rates.
import unicodedata

NAMES = {"strings": 0, "replaced": 0}      # printed strings in which something was withheld; strings the output check replaced
RECOVERY_NAME = "<recovery-password-shaped name withheld>"
ID_TEXT = "<identifier-shaped text withheld>"
SECRET_TEXT = "<secret-shaped text withheld>"
LONG_TEXT = "<text too long to judge withheld>"
CHECKED = "<withheld by the output check>"
MAX_JUDGED = 4096        # characters judged in one string (a name, a component, a header string); longer is withheld whole
MAX_RUN = 256            # the longest run of name characters judged in a string that holds a `/`
_NAME_RUN = re.compile(r"[A-Za-z0-9_+%-]+")
_RECOVERY_SHAPE = re.compile(r"[0-9]{6}(?:[^0-9A-Za-z]{0,3}[0-9]{6}){7}")      # no look-arounds: a digit glued to the first or last group hides nothing
_SIX_SPACED = re.compile(r"(?<![0-9])(?:[0-9]{6} ){3,}[0-9]{6}(?![0-9])")
_GROUP = re.compile(r"(?<![A-Za-z0-9])[A-Za-z0-9]{4,6}(?![A-Za-z0-9])")
_ALNUM_RUN = re.compile(r"[A-Za-z0-9]{8,}")
_KNOWN_RUNS = frozenset(("System32", "SysWOW64", "Wow6432Node", "Windows10", "Windows11", "Windows7", "Windows8", "Windows2000", "Windows2003"))
_WORD_TOKEN = re.compile(r"[A-Z]+(?![a-z])|[A-Z]?[a-z]+")
_NAMED = re.compile(r"(?i)(?<![A-Za-z0-9])(?:pass(?:word|wd|phrase)?|pwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|credential|auth)"
                    r"[A-Za-z0-9_-]{0,16}[ \t]*[=:][ \t]*([^\s\"'&;,/\\<][^\s\"'&;,/\\]*)")
_CACHE = {}
_CACHE_BYTES = [0]


def _chains(text):
    """Spans of groups of 4 to 6 characters joined by one `-`, `_` or `.`: 3 or more digit-only groups, or 4 or more that each hold a digit or are all capitals."""
    chain = []
    for m in _GROUP.finditer(text):
        g = m.group()
        joins = any(c.isdigit() for c in g) or g.isupper()
        if chain and joins and m.start() == chain[-1][1] + 1 and text[chain[-1][1]] in "-_.":
            chain.append((m.start(), m.end(), g.isdigit()))
            continue
        yield from _close(chain)
        chain = [(m.start(), m.end(), g.isdigit())] if joins else []
    yield from _close(chain)


def _close(chain):
    if len(chain) >= 4 or (len(chain) >= 3 and all(c[2] for c in chain)):
        yield chain[0][0], chain[-1][1]


def _wordy(run, caps=1 << 30):
    """A letters-only run that reads as words: one lowercase word (22 letters at most), one all-capital run, or camel case: capitalised
    words and capital runs (acronyms), of which at most a quarter are shorter than 3 letters (one short part is let through in a two-part name whose second part has 5 letters or more: MyDocument)."""
    if run.islower():
        return len(run) <= 22
    if run.isupper():
        return len(run) <= caps
    tokens = _WORD_TOKEN.findall(run)
    return "".join(tokens) == run and all(len(t) <= 22 for t in tokens) and sum(1 for t in tokens if len(t) < 3) <= max(len(tokens) // 4, 1 if len(tokens) == 2 and len(tokens[1]) >= 5 else 0)


def _runs(text):
    for m in _ALNUM_RUN.finditer(text):
        t = m.group()
        if t in _KNOWN_RUNS:
            continue
        if t.isdigit():
            if len(t) >= 10:
                yield m.span()
        elif any(c.isdigit() for c in t) or not _wordy(t):
            yield m.span()


def _spans(text):
    """(start, end, secret) of what a string shows that is shaped like an identifier (secret False) or like a secret (True), merged."""
    found = []
    for m in _NAMED.finditer(text):
        found.append((m.start(1), m.end(1), True))
    for rx in (_USERINFO, _BARE_USERINFO):
        for m in rx.finditer(text):
            found.append((m.start(), m.end(), True))
    for m in _SIX_SPACED.finditer(text):
        found.append((m.start(), m.end(), False))
    for a, b in list(token_spans(text)) + list(_chains(text)) + list(_runs(text)):
        found.append((a, b, False))
    found.sort()
    merged = []
    for a, b, secret in found:
        if merged and a <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], b), merged[-1][2] or secret)
        else:
            merged.append((a, b, secret))
    return merged


# Cyrillic and Greek letters that are written like Latin ones: a pair is (the letter, the Latin letter it is read as).
_LOOKALIKE_PAIRS = ("\u0430a\u0441c\u0435e\u043eo\u0440p\u0445x\u0443y\u0456i\u0458j\u0455s\u0501d\u04bbh\u0410A\u0412B\u0415E\u041aK\u041cM\u041dH"
                    "\u041eO\u0420P\u0421C\u0422T\u0425X\u0406I\u0408J\u0405S\u0423Y\u0391A\u0392B\u0395E\u0396Z\u0397H\u0399I\u039aK\u039cM"
                    "\u039dN\u039fO\u03a1P\u03a4T\u03a5Y\u03a7X\u03bfo\u03bdv\u03b9i\u03c1p")
_LOOKALIKES = {ord(_LOOKALIKE_PAIRS[i]): _LOOKALIKE_PAIRS[i + 1] for i in range(0, len(_LOOKALIKE_PAIRS), 2)}


def _fold(text):
    if text.isascii():
        return text
    return unicodedata.normalize("NFKC", "".join(c for c in text if unicodedata.category(c) != "Cf")).translate(_LOOKALIKES)


def _unjudgeable(text):
    """A string the token rule of the WITHHOLDING block must not be given: too long, or a long run of name characters beside a `/`."""
    return len(text) > MAX_JUDGED or ("/" in text and any(len(run) > MAX_RUN for run in _NAME_RUN.findall(text)))


def _judge(text, whole):
    """(the text as it may be shown, whether anything was withheld). `whole`: a recovery-password shape withholds the whole string."""
    if len(text) < 6:
        return text, False
    if _unjudgeable(text):
        return LONG_TEXT, True
    key = (text, whole)
    if key in _CACHE:
        return _CACHE[key]
    folded = _fold(text)
    if folded is not text and _unjudgeable(folded):
        return _remember(key, (LONG_TEXT, True))
    hit = False
    if _RECOVERY_SHAPE.search(text) or _RECOVERY_SHAPE.search(folded):
        if whole:
            return _remember(key, (RECOVERY_NAME, True))
        text, hit = _RECOVERY_SHAPE.sub(RECOVERY_NAME, folded), True
        folded = text
    spans = _spans(text)
    if folded != text and sum(b - a for a, b, _s in _spans(folded)) > sum(b - a for a, b, _s in spans):
        return _remember(key, (ID_TEXT, True))
    if spans:
        parts, last = [], 0
        for a, b, secret in spans:
            parts.append(text[last:a])
            parts.append(SECRET_TEXT if secret else ID_TEXT)
            last = b
        parts.append(text[last:])
        text, hit = "".join(parts), True
    return _remember(key, (text, hit))


def _remember(key, out):
    # bounded by the number of strings and by their size: 100,000 strings of a few kilobytes each are not a cache
    if len(_CACHE) < 100000 and _CACHE_BYTES[0] < (16 << 20):
        _CACHE[key] = out
        _CACHE_BYTES[0] += len(key[0]) + len(out[0])
    return out


def withhold(text):
    """A string of evidence text (a header field, a diagnostic, a string from a header) as it may be printed."""
    if not isinstance(text, str):
        return text
    out, hit = _judge(text, False)
    if hit:
        NAMES["strings"] += 1
    return out


def shown(path, count=True):
    """A path or a member name as it may be printed: every component judged by itself, a separator kept."""
    if not isinstance(path, str):
        return path
    if len(path) > 2 * MAX_JUDGED:      # a path is judged piece by piece: a name of a few such pieces is not a name
        NAMES["strings"] += 1 if count else 0
        return LONG_TEXT
    hit = False
    # A recovery password cut at the separators of the path ("123456-123456/123456-..."): the separators of a path join its groups.
    for candidate in ((path,) if path.isascii() else (path, _fold(path))):
        cut = _RECOVERY_SHAPE.sub(lambda m: RECOVERY_NAME if ("/" in m.group() or "\\" in m.group()) else m.group(), candidate)
        if cut != candidate:
            path, hit = cut, True
            break
    pieces = re.split(r"([/\\])", path)
    for i in range(0, len(pieces), 2):
        pieces[i], one = _judge(pieces[i], True)
        hit = hit or one
    if hit and count:
        NAMES["strings"] += 1
    return "".join(pieces)


# Layer 2: written apart from the rules above, over everything that is written. A string it finds suspect is replaced whole.
_CHECK_QUICK = re.compile(r"(?i)[0-9]{6}|PRIVATE KEY|[A-Za-z0-9+_=-]{24}|[0-9a-f]{16}|//[^/?#\s@]+@|pass|pwd|secret|token|api[_-]?key|AKIA|ASIA|gh.?_|github_pat|xox|eyJ|sk-|AIza|glpat|npm_")
_CHECK_PREFIX = re.compile(r"(?:AKIA|ASIA)[0-9A-Z]{12}|gh[pousr]_[A-Za-z0-9]{16}|github_pat_[A-Za-z0-9_]{16}|xox[abeprs]-[A-Za-z0-9]{8}|eyJ[A-Za-z0-9_-]{8}"
                           r"|sk-[A-Za-z0-9_-]{16}|AIza[0-9A-Za-z_-]{16}|glpat-[A-Za-z0-9_-]{12}|npm_[A-Za-z0-9]{16}")
_CHECK_DIGITS = re.compile(r"(?<![0-9])(?:[0-9]{6}[-_. ]?){8}(?![0-9])|[0-9]{6}(?:[-_. ][0-9]{6}){7}")
_CHECK_PEM = re.compile(r"-----BEGIN [A-Z ]{0,40}PRIVATE KEY|PRIVATE KEY-----")
_CHECK_RUN = re.compile(r"[A-Za-z0-9+_=-]{24,}")
_CHECK_HEX = re.compile(r"(?<![0-9A-Za-z])(?=[0-9]*[a-fA-F])(?=[a-fA-F]*[0-9])[0-9a-fA-F]{16,}(?![0-9A-Za-z])")     # 16 or more hex digits, letters and digits both
_CHECK_USERINFO = re.compile(r"(?<=//)[^/?#\s@]{1,128}@")
_CHECK_VALUE = re.compile(r"(?i)(?:pass(?:word|wd|phrase)?|pwd|secret|token|api[_-]?key)[A-Za-z0-9_-]{0,16}[ \t]*[=:][ \t]*[^\s\"'<>]{6,}")
OWN_KEYS = {"all_results", "values_file", "paths_note"}      # strings the tool made itself


_UUID = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")


def _suspect(text):
    if not text.isascii():      # full-width and invisible forms are read as the text they imitate
        text = unicodedata.normalize("NFKC", "".join(c for c in text if unicodedata.category(c) != "Cf"))
    if not _CHECK_QUICK.search(text) or _UUID.fullmatch(text):
        return False
    if _CHECK_DIGITS.search(text) or _CHECK_PEM.search(text) or _CHECK_VALUE.search(text) or _CHECK_PREFIX.search(text) \
            or _CHECK_HEX.search(text) or _CHECK_USERINFO.search(text):
        return True
    for m in _CHECK_RUN.finditer(text):
        run = m.group()
        if re.fullmatch(r"[0-9a-fA-F]{32,}", run):
            return True
        flips = sum(1 for a, b in zip(run, run[1:]) if a.isdigit() != b.isdigit() and a.isalnum() and b.isalnum())
        if flips >= 6:
            return True
    return False


def seal(value, key=None):
    """The value with every string the check finds suspect replaced (a dict's keys too). Counted in NAMES['replaced']."""
    if isinstance(value, str):
        if key in OWN_KEYS or len(value) < 8 or not _suspect(value):
            return value
        NAMES["replaced"] += 1
        return CHECKED
    if isinstance(value, dict):
        out = {}
        for k, v in value.items():
            if isinstance(k, str) and len(k) >= 8 and _suspect(k):
                NAMES["replaced"] += 1
                k = CHECKED + "#%d" % NAMES["replaced"]
            out[k] = seal(v, k)
        return out
    if isinstance(value, (list, tuple)):
        return [seal(v, key) for v in value]
    return value
# END SHARED NAMES


# BEGIN SHARED STOP
# The same text is in recovery_key_scan, archive_probe and crypto_id (a pack test holds the copies equal). SIGTERM, SIGINT and SIGHUP end the
# tool with ONE JSON answer and the exit status 128 + the signal, with no traceback and no temporary file left. A tool that scans
# (cooperative) only notes the signal: the scan reads stop_wanted() between windows and files, finishes its pages and prints a partial
# answer. If it is not finished GRACE_SECONDS later (a read that never returns), or a second signal comes, the stop is hard: the cleanup
# steps run (a program the tool started is killed, a values file is closed), the temporary files of the pages are removed, the last word
# is printed and the process ends. The tool's own clock (set_deadline) is below the manifest's timeout and is backed by the same hard stop:
# GRACE_SECONDS after the deadline a read that has not returned (a file on a volume that is not there, a pipe nobody writes) no longer holds
# the tool. SIGALRM ends it when the read can be interrupted, and a watchdog thread, which needs neither a signal nor the read to return,
# ends it when not; either prints ONE JSON answer, status partial, and exits 0. A page fault in a mapped file can be ended by neither (it
# holds the interpreter): a tool that maps a file reads the part it maps through a descriptor first, where the thread can run.
import signal
import threading
import time

GRACE_SECONDS = 5
STOP = {"signal": None, "deadline": None, "limit": None, "last_word": None, "cooperative": False, "cleanup": [], "answered": False,
        "owner": None, "hard_due": None}
_STOP_LOCK = threading.RLock()
_STOP_DONE = threading.Event()


def set_deadline(seconds):
    STOP["limit"] = seconds
    STOP["deadline"] = time.monotonic() + seconds
    arm_hard_stop(seconds + GRACE_SECONDS)
    threading.Thread(target=_watchdog, name="hard-stop", daemon=True).start()


def arm_hard_stop(seconds):
    """The hard stop is due in `seconds` at the latest (an earlier one stays): as SIGALRM, and as the time the watchdog waits for."""
    due = time.perf_counter() + seconds
    if STOP["hard_due"] is None or due < STOP["hard_due"]:
        STOP["hard_due"] = due
    left = signal.getitimer(signal.ITIMER_REAL)[0]
    signal.setitimer(signal.ITIMER_REAL, seconds if left <= 0 else min(seconds, left))


def disarm_stop():
    """No hard stop is wanted any more (the answer is going out, or the tool ends with an error): the timer and the watchdog stand down."""
    STOP["hard_due"] = None
    _STOP_DONE.set()
    signal.setitimer(signal.ITIMER_REAL, 0)


def _watchdog():
    while not _STOP_DONE.wait(0.2):
        due = STOP["hard_due"]
        if due is not None and time.perf_counter() >= due:
            hard_stop(STOP["signal"])


def stand_by():
    """When another thread is ending the tool, wait for it to do so: nothing else may print."""
    if STOP["owner"] not in (None, threading.get_ident()):
        while True:
            time.sleep(3600)


def out_of_time():
    return STOP["deadline"] is not None and time.monotonic() > STOP["deadline"]


def stop_wanted():
    return STOP["signal"] is not None or out_of_time()


def stop_cause():
    if STOP["signal"] is not None:
        return "stopped by signal %d" % STOP["signal"]
    return "the time limit (max_seconds %s) was reached" % STOP["limit"]


def remove_pending_pages():
    """Remove the temporary file of every page that is still being written."""
    for page in list(globals().get("PAGES", [])):
        tmp = getattr(page, "_tmp", None)
        if tmp is not None:
            try:
                os.unlink(tmp)
            except OSError:
                pass


def hard_stop(signum):
    """End the tool now. `signum` is the signal that asked for it; None when the clock did: the answer is then partial and the exit status 0."""
    with _STOP_LOCK:
        if signum is None and STOP["answered"]:     # the answer is being written: let it be written
            STOP["hard_due"] = None
            return
        if STOP["owner"] in (None, threading.get_ident()):
            STOP["owner"] = threading.get_ident()
            mine = True
        else:
            mine = False
    if not mine:
        stand_by()
    for step in list(STOP["cleanup"]):
        try:
            step()
        except Exception:  # noqa: BLE001 - a cleanup step is best effort
            pass
    remove_pending_pages()
    if STOP["last_word"] and not STOP["answered"]:
        try:
            STOP["last_word"](signum)
        except Exception:  # noqa: BLE001
            pass
    os._exit(128 + signum if signum else 0)


def _on_stop_signal(signum, _frame):
    if STOP["cooperative"] and STOP["signal"] is None:
        STOP["signal"] = signum
        arm_hard_stop(GRACE_SECONDS)
        return
    hard_stop(STOP["signal"] or signum)


def _on_stop_alarm(_signum, _frame):
    hard_stop(STOP["signal"])


def install_stop(last_word=None, cooperative=False):
    STOP["last_word"], STOP["cooperative"] = last_word, cooperative
    for signum in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(signum, _on_stop_signal)
    signal.signal(signal.SIGALRM, _on_stop_alarm)


def interrupted_answer(signum, **extra):
    if signum is None:       # the clock ran out, and then GRACE_SECONDS more, with a read that had not returned
        print(json.dumps({"status": "partial", "partial": True, "interrupted": True, "hard_stopped": True,
                          "stopped_by": "the tool's time limit (%s seconds) was reached" % STOP["limit"],
                          "status_basis": "the tool's time limit (%s seconds) and %d seconds more passed while a read had not returned (a file on a "
                                          "volume or share that is not available, or a pipe); the tool was ended there, and nothing it had read is "
                                          "an answer" % (STOP["limit"], GRACE_SECONDS), **extra}), flush=True)
        return
    print(json.dumps({"error": "stopped by signal %d before the answer was complete" % signum, "status": "interrupted",
                      "status_basis": "the tool was stopped by signal %d; nothing it had read is an answer" % signum,
                      "signal": signum, **extra}), flush=True)


def claim_answer():
    """Take the one answer (an answer or an error): the stop is disarmed, the stop signals are held back, and `answered` is set under the
    lock, so that a watchdog that has read its due time but not yet taken the lock finds the answer claimed and prints nothing. When the
    stop was claimed first, wait for the thread that has it to end the tool."""
    disarm_stop()
    held = {signal.SIGTERM, signal.SIGINT, signal.SIGHUP, signal.SIGALRM}
    signal.pthread_sigmask(signal.SIG_BLOCK, held)
    with _STOP_LOCK:
        mine = STOP["owner"] in (None, threading.get_ident())
        if mine:
            STOP["answered"] = True
    if not mine:
        stand_by()


def emit(answer):
    """Print the answer once, with the stop signals held back until it is out, and leave with 128 + the signal if one was noted."""
    claim_answer()
    text = json.dumps(seal(answer), indent=2, ensure_ascii=True)
    sys.stdout.write(text + "\n")
    sys.stdout.flush()
    if STOP["signal"] is not None:
        os._exit(128 + STOP["signal"])
# END SHARED STOP


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
# walk has no bound but the number of processes. Two cases leave the tree running: a ps that needs more than PS_WAIT
# seconds, and a sandbox that denies both libproc and ps (macOS).
try:
    import ctypes
except ImportError:  # pragma: no cover
    ctypes = None

STATE = {"last_word": None}    # what to do, with the signal number, when the tool is stopped by a signal
ACTIVE = []                    # the programs running now

def _die_with_parent():  # runs in the child between fork and exec
    try:
        ctypes.CDLL(None).prctl(1, signal.SIGKILL)   # PR_SET_PDEATHSIG
    except Exception:  # noqa: BLE001
        pass


def spawn(argv, **kwargs):
    kwargs.setdefault("stdin", subprocess.DEVNULL)
    if sys.platform.startswith("linux") and ctypes is not None:
        kwargs["preexec_fn"] = _die_with_parent
    return subprocess.Popen(argv, **kwargs)


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
    found, seen, stack = [], {pid}, [pid]
    while stack:
        for child in kids.get(stack.pop(), []):
            if child not in seen:
                seen.add(child)
                found.append(child)
                stack.append(child)
    return found


def descendants(pid):
    """Every process below `pid` (never one beside it): from /proc where there is one, else from libproc, else from ps
    (given PS_WAIT seconds). libproc is believed when it lists a child; an empty answer is believed only when libproc has
    just listed this tool's own child `pid` (a library that answers nothing for a live child is not working, as in a
    sandbox that denies it), and otherwise ps is asked."""
    kids = {}
    try:
        if os.path.isdir("/proc/self"):
            for entry in os.listdir("/proc"):
                if entry.isdigit():
                    try:
                        with open("/proc/%s/stat" % entry, "rb") as fh:
                            fields = fh.read().rsplit(b")", 1)[1].split()
                        kids.setdefault(int(fields[1]), []).append(int(entry))
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
                return found
            if first is not None and pid in (_children_libproc(os.getpid()) or []):
                return []
            out = subprocess.run(["ps", "-A", "-o", "pid=,ppid="], capture_output=True, text=True, timeout=PS_WAIT).stdout
            for line in out.splitlines():
                parts = line.split()
                if len(parts) == 2 and parts[0].isdigit() and parts[1].isdigit():
                    kids.setdefault(int(parts[1]), []).append(int(parts[0]))
    except (OSError, subprocess.SubprocessError):
        return []
    return _below(kids, pid)


def kill_tree(proc):
    """Kill the program and everything it started. The children are listed first: once the parent is gone they are
    adopted by init and can no longer be found below it. A program already waited for is not touched: its pid is free to
    be another process's, and the walk below it would be that process's children."""
    if proc.poll() is not None:
        return
    victims = descendants(proc.pid)
    try:
        proc.kill()
    except OSError:
        pass
    for pid in victims:
        try:
            os.kill(pid, signal.SIGKILL)
        except OSError:
            pass


def _on_signal(signum, _frame):
    for proc in list(ACTIVE):
        kill_tree(proc)
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
        out, err = proc.communicate(timeout=max(1.0, seconds))
        return proc.returncode, out, err, False
    except subprocess.TimeoutExpired:
        kill_tree(proc)
        out, err = proc.communicate()
        return None, out, err, True
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


class SealedPage(NoReplacePage):
    """A page whose every row passes the output check before it is kept or written."""

    def add(self, row: object) -> None:
        super().add(seal(row))


ZIP_ENCRYPTED = 0x0001
ZIP_STRONG = 0x0040
ZIP_UTF8_NAME = 0x0800
CD_SIGNATURE = 0x02014B50
MAX_METADATA_DEFAULT = 32 << 20
DEFAULT_SECONDS = 100           # the manifest allows 120; the tool stops at this and still prints what it has
MAX_SECONDS = 110
# The 7-Zip AES-256 + SHA-256 coder id. In an encoded (packed) header it means
# the header itself is encrypted, so the names need the password.
SEVENZIP_AES = b"\x06\xf1\x07\x01"
SEVENZIP_PROGRAMS = ("7z", "7zz", "7za")
SEVENZIP_TIMEOUT = 60
# Given to 7z so that it never stops to ask for one: an archive whose header is
# encrypted then fails to open, which is the answer wanted. It is not a secret.
NO_PASSWORD = "dfirswarm-no-password"
ASCII_RUN = re.compile(rb"[\x20-\x7e]{6,}")
WIDE_RUN = re.compile(rb"(?:[\x20-\x7e]\x00){3,}")
ENCRYPTED_ARCHIVE = re.compile(r"(?i)(can ?not|can't) open encrypted archive|wrong password")
MARKER_OFFSETS = 20
MARKER_COUNT_CAP = 10000
NEXT_DOCUMENT_READER = ("none is provided by this pack: a structural document reader (doc_structure, planned for the "
                        "reverse-engineering pack) is not available yet")
SEARCH = {"cut": False}


def fail(message, **extra):
    claim_answer()
    remove_pending_pages()
    print(json.dumps(seal({"error": message, "status": "failed",
                           "status_basis": "the tool stopped with an error (see error); no container was read", **extra}), ensure_ascii=True))
    raise SystemExit(1)


def describe(exc):
    return withhold("%s: %s" % (type(exc).__name__, getattr(exc, "strerror", None) or str(exc)))


WINDOW = 8 << 20


def touch(fd, start, end):
    """Read [start, end) through the descriptor, a megabyte at a time, and drop it: the pages are in memory before the mapping is used.

    A page of a mapped file that is not in memory (a file kept on a cloud volume, on a share that does not answer) stops the whole
    interpreter until it comes: no signal handler and no other thread, the watchdog included, can run in the meantime. A read stops only
    itself, and the watchdog ends the tool if it does not return. True when all of it was read; False when the clock or a signal
    stopped the reading; an OSError when the file ends before `end` (it shrank after it was mapped).
    """
    pos = start
    while pos < end:
        if stop_wanted():
            return False
        got = os.pread(fd, min(1 << 20, end - pos), pos)
        if not got:
            raise OSError("the file ends before the %d bytes that were mapped: it changed while it was read" % end)
        pos += len(got)
    return True


def extra_fields(extra):
    """The (id -> data) of a ZIP extra field block; the first of an id wins."""
    out, i = {}, 0
    while i + 4 <= len(extra):
        ident, size = struct.unpack_from("<HH", extra, i)
        out.setdefault(ident, extra[i + 4:i + 4 + size])
        i += 4 + size
    return out


def filetime_iso(value):
    """A Windows FILETIME (100 ns since 1601-01-01 UTC) as ISO 8601 UTC, keeping the fraction."""
    seconds, ticks = divmod(value, 10_000_000)
    moment = datetime(1601, 1, 1, tzinfo=timezone.utc) + timedelta(seconds=seconds)
    return moment.strftime("%Y-%m-%dT%H:%M:%S") + ".%07dZ" % ticks


def recorded_time(fields):
    """An extended timestamp a ZIP entry records beside its DOS time, with its source, or (None, None)."""
    try:
        ntfs = fields.get(0x000A)
        if ntfs and len(ntfs) >= 4:
            i = 4
            while i + 4 <= len(ntfs):
                tag, size = struct.unpack_from("<HH", ntfs, i)
                if tag == 1 and size >= 8 and i + 4 + 8 <= len(ntfs):
                    return filetime_iso(struct.unpack_from("<Q", ntfs, i + 4)[0]), "NTFS times (extra 0x000a), 100 ns, UTC"
                i += 4 + size
        ut = fields.get(0x5455)
        if ut and len(ut) >= 5 and ut[0] & 1:
            when = datetime.fromtimestamp(struct.unpack_from("<i", ut, 1)[0], tz=timezone.utc)
            return when.strftime("%Y-%m-%dT%H:%M:%SZ"), "extended timestamp (extra 0x5455), 1 s, UTC"
    except (OverflowError, ValueError, OSError):
        return None, "an extended timestamp is recorded but its value is out of range"
    return None, None


def aes_of(fields):
    """The WinZip AES extra field (0x9901): AE version, strength in bits, the real method."""
    data = fields.get(0x9901)
    if not data or len(data) < 7 or data[2:4] != b"AE":
        return None
    version, strength, method = struct.unpack_from("<H", data, 0)[0], data[4], struct.unpack_from("<H", data, 5)[0]
    return {"ae_version": version, "strength_bits": {1: 128, 2: 192, 3: 256}.get(strength), "method": method}


EOCD_SIGNATURE = b"PK\x05\x06"


def end_record_at(tail, at, tail_start):
    """The End record whose signature is at `at` in `tail` (the last bytes of the file, which start at `tail_start`), or None when its 22 bytes do not fit.

    The Zip64 end record is read wherever a Zip64 locator sits right before the End
    record, whatever the End record says (a reader that follows the locator only
    when the End record holds 0xFFFF or 0xFFFFFFFF can be told "one entry" while the
    Zip64 record says millions: Python's zipfile follows the locator always, and so
    does this). The record is taken from the 56 bytes before the locator, as zipfile
    does, and the locator's own offset is checked against it. `after_comment` is the
    number of bytes between the end of the record's comment and the end of the file:
    0 for a record that ends the file, negative when the comment is declared longer
    than the file holds.
    """
    if at + 22 > len(tail):
        return None
    _sig, _disk, _cd_disk, _n_disk, n_total, cd_size, cd_offset, comment_len = struct.unpack_from("<IHHHHIIH", tail, at)
    after = len(tail) - (at + 22 + comment_len)
    out = {"entries": n_total, "cd_bytes": cd_size, "cd_offset": cd_offset, "comment_bytes": comment_len,
           "zip64": False, "eocd_at": tail_start + at, "after_comment": after}
    if at >= 20 and tail[at - 20:at - 16] == b"PK\x06\x07":
        out["zip64_locator"] = True
        rec = tail[at - 20 - 56:at - 20] if at - 20 - 56 >= 0 else b""
        if len(rec) == 56 and rec[:4] == b"PK\x06\x06":
            out["entries"], out["cd_bytes"], out["cd_offset"] = struct.unpack_from("<QQQ", rec, 32)
            out["zip64"] = True
            if struct.unpack_from("<Q", tail, at - 20 + 8)[0] != out["eocd_at"] - 20 - 56:
                out["zip64_locator_disagrees"] = True
    out["zip64_unresolved"] = bool((n_total == 0xFFFF or cd_size == 0xFFFFFFFF or cd_offset == 0xFFFFFFFF) and not out["zip64"])
    return out


def directory_starts(fh, record, size):
    """Does the central directory this End record declares start with a central directory signature (or is it an empty archive's)?"""
    if record["cd_bytes"] == 0:
        return record["entries"] == 0
    start = record["eocd_at"] - (76 if record["zip64"] else 0) - record["cd_bytes"]
    if start < 0 or record["cd_bytes"] > size:
        return False
    fh.seek(start)
    return fh.read(4) == b"PK\x01\x02"


def read_eocd(path, size):
    """The End Of Central Directory record of the file, or None.

    A comment may hold anything, an End record included, so the last signature in the
    file is not necessarily the archive's own (a reader that takes it lists the
    comment's record: 0 entries for an archive that holds some). The records whose
    comment ends exactly at the end of the file, and whose directory starts with a
    directory signature, are the candidates; with several, the one that declares the
    most entries is read, and the others are named in `other_records`, so that the
    caller can say that they disagree. A sound record of another archive that lies
    wholly before the chosen archive (a second archive appended to the first) is
    named the same way. With none, the last signature is read as before and
    `after_comment` says that no record ends the file.
    """
    tail_len = min(size, 65535 + 22 + 20 + 56)
    with open(path, "rb") as fh:
        fh.seek(size - tail_len)
        tail = fh.read(tail_len)
        records, at = [], tail.rfind(EOCD_SIGNATURE)
        while at >= 0:
            record = end_record_at(tail, at, size - tail_len)
            if record is not None:
                records.append(record)         # the last one in the file first
            at = tail.rfind(EOCD_SIGNATURE, 0, at + 3)
        sound = [r for r in records if directory_starts(fh, r, size)]
    if not records:
        return None
    exact = [r for r in records if r["after_comment"] == 0]
    good = [r for r in sound if r["after_comment"] == 0]
    if good:
        chosen = min(good, key=lambda r: (-r["entries"], r["eocd_at"]))
    elif exact:
        chosen = exact[0]
    elif sound:
        chosen = sound[0]
    else:
        chosen = records[0]
    pool = good
    if chosen["entries"] == 0 and chosen["cd_bytes"] == 0:
        # An empty archive's record at the end of a file that holds a sound, non-empty one before it (7-Zip lists that one): the
        # record that is not empty is read, and the other is named.
        pool = sound
        richer = [r for r in sound if r["entries"] > 0]
        if richer:
            chosen = min(richer, key=lambda r: (-r["entries"], r["eocd_at"]))
    # An archive in front of the chosen one in the same file (a second archive appended: 7-Zip lists the first, `zipfile` the last): a
    # sound record that does not end the file and whose whole archive, comment included, ends before the chosen archive begins. The
    # chosen archive begins where its own directory offset says. A stored ZIP inside a member (a jar that holds one) puts a sound
    # record inside the chosen archive, after that start, and is not counted; where the start cannot be worked out (an unresolved Zip64
    # offset, an offset that does not fit the file) nothing is counted.
    begins = chosen["eocd_at"] - (76 if chosen["zip64"] else 0) - chosen["cd_bytes"] - chosen["cd_offset"]
    if chosen["zip64_unresolved"] or begins < 0:
        begins = -1
    separate = [r for r in sound if r is not chosen and r["after_comment"] > 0 and r["eocd_at"] + 22 + r["comment_bytes"] <= begins]
    pool = pool + [r for r in separate if not any(r is p for p in pool)]
    start = chosen["eocd_at"] - (size - tail_len)
    chosen["after_comment_zero"] = chosen["after_comment"] > 0 and not tail[start + 22 + chosen["comment_bytes"]:].strip(b"\x00")
    # Another archive is named whatever it declares (two archives of one shape differ in their flags); a record in a comment, only when it
    # declares something else.
    others = [r for r in pool if r is not chosen and (any(r is q for q in separate) or (r["entries"], r["cd_bytes"]) != (chosen["entries"], chosen["cd_bytes"]))]
    chosen["other_record_count"] = len(others)
    chosen["other_records"] = [{"offset": r["eocd_at"], "entries": r["entries"], "central_directory_bytes": r["cd_bytes"],
                                "comment_bytes": r["comment_bytes"]} for r in others[:8]]
    return chosen


class CentralDirectory:
    """The central directory read in blocks: nothing of it is held but the block being read."""

    def __init__(self, fh, start, length):
        self.fh, self.left, self.buf, self.pos = fh, length, b"", 0
        fh.seek(start)

    def take(self, n):
        """The next n bytes, or None when fewer than n remain in the directory."""
        while len(self.buf) - self.pos < n:
            if self.left <= 0:
                return None
            more = self.fh.read(min(1 << 20, self.left))
            if not more:
                self.left = 0
                return None
            self.left -= len(more)
            self.buf = self.buf[self.pos:] + more
            self.pos = 0
        out = self.buf[self.pos:self.pos + n]
        self.pos += n
        return out

    def remaining(self):
        return len(self.buf) - self.pos + self.left


def zip64_values(fields, usize, csize, offset):
    """The sizes and offset a Zip64 extra field replaces (in the order uncompressed, compressed, offset), or the values as they are."""
    z = fields.get(0x0001)
    if z is None or 0xFFFFFFFF not in (usize, csize, offset):
        return usize, csize, offset, None
    at, values = 0, []
    for value in (usize, csize, offset):
        if value == 0xFFFFFFFF:
            if at + 8 > len(z):
                return usize, csize, offset, "a Zip64 extra field too short for the sizes it must hold"
            value = struct.unpack_from("<Q", z, at)[0]
            at += 8
        values.append(value)
    return values[0], values[1], values[2], None


def probe_zip(path, size, limit, max_metadata):
    out = {"container": "ZIP", "protection": "structural: the central directory's flags and extra fields"}
    eocd = read_eocd(path, size)
    if eocd is None:
        return {**out, "listing": "failed", "protected": None, "status": "failed",
                "status_basis": "a ZIP signature but no End Of Central Directory record in the last 64 KiB: nothing was listed",
                "error": "a ZIP signature but no End Of Central Directory record in the last 64 KiB: the archive is "
                         "truncated, damaged or carved short",
                "not_determined": ["the member list", "which members are encrypted"]}
    out["entry_count_declared"] = eocd["entries"]
    out["central_directory_bytes"] = eocd["cd_bytes"]
    if eocd.get("zip64"):
        out["zip64"] = True
    # What makes the End record less than certain: another record that ends the file (a comment can hold one) and says something else,
    # or no record that ends it (bytes after the comment, or a comment declared longer than the file).
    doubts = []
    if eocd["other_record_count"]:
        out["end_records_disagree"] = {"read": {"offset": eocd["eocd_at"], "entries": eocd["entries"], "central_directory_bytes": eocd["cd_bytes"]},
                                       "others": eocd["other_records"], "others_counted": eocd["other_record_count"]}
        doubts.append("the end of the file holds %d other End record%s with a different directory (an End record can sit in another's comment): "
                      "the one that declares the most entries was read" % (eocd["other_record_count"], "" if eocd["other_record_count"] == 1 else "s"))
    if eocd["after_comment"] > 0 and eocd["after_comment_zero"]:
        out["trailing_zero_bytes"] = eocd["after_comment"]
    elif eocd["after_comment"] > 0:
        out["trailing_bytes_after_comment"] = eocd["after_comment"]
        doubts.append("%d bytes that are not zeros follow the End record's comment, so no End record ends the file: the last one was read" % eocd["after_comment"])
    elif eocd["after_comment"] < 0:
        out["end_record_comment_overruns_by"] = -eocd["after_comment"]
        doubts.append("the End record declares a comment %d bytes longer than the file holds: it may be cut short or not an End record" % -eocd["after_comment"])
    if doubts:
        out["end_record_doubts"] = doubts
    # The bound is on what the archive DECLARES, whatever record it is declared in: a directory over the limit, over the file, or
    # claiming more entries than the limit can hold (46 bytes at least each) is not read.
    reason = None
    if eocd["cd_bytes"] > max_metadata:
        reason = ("the central directory is %d bytes (%d entries declared), above max_metadata_bytes (%d): it was not loaded. "
                  "Raise max_metadata_bytes to list it" % (eocd["cd_bytes"], eocd["entries"], max_metadata))
    elif eocd["entries"] > max_metadata // 46:
        reason = ("%d entries are declared, more than max_metadata_bytes (%d) can hold at 46 bytes an entry: the directory was not "
                  "loaded. Raise max_metadata_bytes to list it" % (eocd["entries"], max_metadata))
    elif eocd["cd_bytes"] > size:
        reason = "the central directory is declared as %d bytes, more than the file holds (%d): it was not loaded" % (eocd["cd_bytes"], size)
    if reason:
        return {**out, "listing": "not attempted", "protected": None, "partial": True, "status": "partial",
                "status_basis": "the central directory was not read: %s" % ("over the bound" if "above" in reason or "more than max" in reason else "it does not fit the file"),
                "reason": reason, "not_determined": ["the member list", "which members are encrypted"]}
    cd_start = eocd["eocd_at"] - (76 if eocd["zip64"] else 0) - eocd["cd_bytes"]
    if cd_start < 0:
        return {**out, "listing": "failed", "protected": None, "status": "failed",
                "status_basis": "the central directory does not fit before the End record: nothing was listed",
                "error": "the central directory (%d bytes) does not fit in the bytes before the End Of Central Directory record" % eocd["cd_bytes"],
                "not_determined": ["the member list", "which members are encrypted"]}
    concat = cd_start - eocd["cd_offset"]          # bytes in front of the archive (a self-extracting stub)
    entries = SealedPage("archive_probe", [os.path.realpath(path), "zip entries"], limit)
    encrypted, schemes, problem, count = 0, set(), None, 0
    consumed = 0
    with open(path, "rb") as fh:
        cd = CentralDirectory(fh, cd_start, eocd["cd_bytes"])
        while consumed < eocd["cd_bytes"]:
            if stop_wanted():       # every entry: a name that takes a moment to judge is bounded, but not the number of them
                problem = "%s after %d entries" % (stop_cause(), count)
                break
            fixed = cd.take(46)
            if fixed is None:
                problem = "the central directory ends inside entry %d's header (%d bytes left of %d)" % (count, eocd["cd_bytes"] - consumed, eocd["cd_bytes"])
                break
            (sig, _made, _needed, flags, method, dos_time, dos_date, _crc, csize, usize, nlen, xlen, clen,
             _disk, _iattr, _eattr, offset) = struct.unpack("<IHHHHHHIIIHHHHHII", fixed)
            if sig != CD_SIGNATURE:
                problem = "entry %d does not start with the central directory signature (bad magic number at %d bytes into the directory)" % (count, consumed)
                break
            name_raw, extra, _comment = cd.take(nlen), cd.take(xlen), cd.take(clen)
            if name_raw is None or extra is None or _comment is None:
                problem = "the central directory ends inside entry %d (its name, extra field or comment is cut)" % count
                break
            consumed += 46 + nlen + xlen + clen
            fields = extra_fields(extra)
            usize, csize, offset, extra_problem = zip64_values(fields, usize, csize, offset)
            if flags & ZIP_UTF8_NAME:
                name, encoding = name_raw.decode("utf-8", "surrogateescape"), "UTF-8 (flag 0x800)"
            else:
                name, encoding = name_raw.decode("cp437"), "cp437"
            scheme, is_encrypted, aes = None, bool(flags & ZIP_ENCRYPTED), None
            if is_encrypted:
                encrypted += 1
                aes = aes_of(fields)
                if method == 99:
                    scheme = ("WinZip AES-%s (AE-%d)" % (aes["strength_bits"] or "?", aes["ae_version"])) if aes \
                        else "WinZip AES (the extra field is unreadable)"
                elif flags & ZIP_STRONG:
                    scheme = "strong encryption"
                else:
                    scheme = "ZipCrypto (legacy, weak)"
                schemes.add(scheme)
            y, mo, d = (dos_date >> 9) + 1980, (dos_date >> 5) & 0xF, dos_date & 0x1F
            h, mi, s = dos_time >> 11, (dos_time >> 5) & 0x3F, (dos_time & 0x1F) * 2
            row = {"index": count, "name": shown(name), "name_encoding": encoding, "bytes": usize, "compressed": csize,
                   "header_offset": offset + concat, "method": method,
                   "modified": "%04d-%02d-%02dT%02d:%02d:%02d" % (y, mo, d, h, mi, s),
                   "modified_raw": "dos_date=0x%04x dos_time=0x%04x" % (dos_date, dos_time),
                   "timezone_unknown": True,
                   "encrypted": is_encrypted, "scheme": scheme}
            if extra_problem:
                row["extra_problem"] = extra_problem
            if aes:
                row["aes"] = aes
            utc, source = recorded_time(fields)
            if utc:
                row["modified_utc"], row["modified_utc_source"] = utc, source
            elif source:
                row["modified_utc_problem"] = source
            entries.add(row)
            count += 1
    page = entries.finish()
    out["entries"] = entries.page
    out["entry_count"] = page["matched"]
    out.update(page)
    out["encrypted_entries"] = encrypted
    out["schemes"] = sorted(schemes)
    out["names_readable"] = True
    out["entry_count_matches_declared"] = page["matched"] == eocd["entries"]
    out["time_note"] = ("`modified` is the MS-DOS date and time of the archiving machine's local clock: no zone, 2-second "
                        "resolution (timezone_unknown). `modified_utc`, where present, is a separate recorded time in UTC.")
    out["not_determined"] = ["whether an encrypted member's data is intact or openable", "why or by whom it was encrypted"]
    if problem:
        out["listing"] = "partial"
        out["listing_problem"] = problem
        out["protected"] = True if encrypted else None
        out["status"] = "partial"
        out["status_basis"] = "the member list stops after %d of %d declared entries: %s" % (count, eocd["entries"], problem)
        if doubts:
            out["status_basis"] += "; " + "; ".join(doubts)
        out["not_determined"].insert(0, "the members after the point where the directory could not be read")
        out["partial"] = True
    else:
        matches = out["entry_count_matches_declared"]
        sure = matches and not doubts
        # `protected: false` is said only of a list that is whole and of an End record nothing contradicts.
        out["protected"] = True if encrypted else (False if sure else None)
        out["status"] = "complete" if sure else "partial"
        if sure:
            out["status_basis"] = "every central directory entry was read and the count agrees with the End record"
        else:
            reasons = list(doubts)
            if not matches:
                reasons.insert(0, "every central directory entry was read, but the count (%d) differs from the %d the End record declares" % (count, eocd["entries"]))
            else:
                reasons.insert(0, "every central directory entry was read and the count agrees with the End record read")
            out["status_basis"] = "; ".join(reasons)
        if doubts:
            out["not_determined"].insert(0, "which End record is the archive's, and so whether the list is the archive's whole list")
    return out


def find_7z():
    for name in SEVENZIP_PROGRAMS:
        found = shutil.which(name)
        if found:
            return found
    return None


def list_with_7z(path, limit):
    """List an archive through 7z, bounded in time, never asking for a password.

    Returns (listing, members): `listing` says what happened (status, exit code,
    the first diagnostic lines); `members` is the LosslessPage of members.
    """
    exe = find_7z()
    if exe is None:
        return {"status": "unavailable", "reason": "none of %s is on PATH" % ", ".join(SEVENZIP_PROGRAMS)}, None
    cmd = [exe, "l", "-slt", "-y", "-p" + NO_PASSWORD, "--", path]
    members = SealedPage("archive_probe", [os.path.realpath(path), "7z members"], limit)
    seconds = max(1.0, min(SEVENZIP_TIMEOUT, STOP["deadline"] - time.monotonic() if STOP["deadline"] else SEVENZIP_TIMEOUT))
    info = {"via": os.path.basename(exe), "timeout_seconds": round(seconds)}
    try:
        proc = spawn(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, errors="replace")
    except OSError as exc:
        return {**info, "status": "unavailable", "reason": "7z could not be started: %s" % describe(exc)}, None
    ACTIVE.append(proc)
    timed_out = []
    timer = threading.Timer(seconds, lambda: (timed_out.append(True), kill_tree(proc)))
    timer.start()
    archive, current, in_members, diagnostics, encrypted_message = {}, {}, False, [], False
    seen = {"members": 0, "encrypted": 0, "not_encrypted": 0, "flag_missing": 0}

    def flush():
        nonlocal current
        if current.get("Path") is not None:
            flag = current.get("Encrypted")
            seen["members"] += 1
            seen["encrypted" if flag == "+" else "not_encrypted" if flag == "-" else "flag_missing"] += 1
            members.add({"index": members.total, "name": shown(current["Path"]),
                         "bytes": int(current["Size"]) if current.get("Size", "").isdigit() else None,
                         "packed": int(current["Packed Size"]) if current.get("Packed Size", "").isdigit() else None,
                         "modified_as_printed": withhold(current.get("Modified")) or None, "timezone_unknown": True,
                         "encrypted": True if flag == "+" else (False if flag == "-" else None),
                         "method": withhold(current.get("Method")), "crc": withhold(current.get("CRC")) or None,
                         "attributes": withhold(current.get("Attributes")) or None})
        current = {}

    try:
        for raw in proc.stdout:
            if stop_wanted():
                timed_out.append(True)
                kill_tree(proc)
                break
            line = raw.rstrip("\r\n")
            if not in_members and ENCRYPTED_ARCHIVE.search(line):       # 7z's own message, not a member name that says the same
                encrypted_message = True
            if re.match(r"^(ERROR|WARNING|Errors|Warnings)\b", line) and len(diagnostics) < 5:
                diagnostics.append(withhold(line))
            if line == "----------":
                in_members = True
                continue
            if line == "--" and not in_members:
                continue
            if not line.strip():
                if in_members:
                    flush()
                continue
            key, sep, value = line.partition(" = ")
            if not sep:
                continue
            if not in_members:
                archive.setdefault(key, value)
            else:
                if key == "Path" and current.get("Path") is not None:
                    flush()
                current[key] = value
        flush()
        code = proc.wait()
    finally:
        timer.cancel()
        kill_tree(proc)
        if proc in ACTIVE:
            ACTIVE.remove(proc)
    info["exit_code"] = code
    info["members_seen"] = seen
    if diagnostics:
        info["diagnostics"] = diagnostics
    if archive:
        info["archive"] = {k: withhold(archive[k]) for k in ("Type", "Physical Size", "Headers Size", "Method", "Solid", "Blocks") if k in archive}
    if timed_out:
        return {**info, "status": "timed_out", "reason": "7z was stopped after %d seconds or at the tool's own time limit; %d members were read before it" % (seconds, members.total)}, members
    if code in (0, 1) and archive.get("Type"):
        return {**info, "status": "listed" if code == 0 else "listed_with_warnings"}, members
    if encrypted_message:
        return {**info, "status": "header_encrypted",
                "reason": "7z reports that it cannot open the archive without a password"}, None
    return {**info, "status": "failed", "reason": "7z could not list this file (exit %s)" % code}, None


def probe_7z(view, fd, path, limit, max_metadata):
    """The 32-byte start header points at the real header, at the end of the file.

    That header is either plain (0x01), where the names sit in the clear, or
    encoded (0x17): packed, and encrypted as well when its coder list names AES.
    """
    out = {"container": "7-Zip", "names_readable": None, "protected": None,
           "protection": "7z's own listing where it could read the archive; otherwise a heuristic from the start header"}
    # The header is read in place, through the mapping: nothing of it is copied,
    # and what is searched is the first `searched` bytes from `at`. Each part is read through
    # the descriptor first (touch), so that a stall is a stalled read, which the watchdog ends.
    at, searched, header_cut = 0, 0, None
    out["start_header"] = {}
    sh = out["start_header"]
    if len(view) < 32:
        sh["problem"] = "the file is shorter than the 32-byte start header"
    elif not touch(fd, 0, 32):
        header_cut = stop_cause()
    else:
        start_crc, = struct.unpack_from("<I", view, 8)
        sh["crc_ok"] = zlib.crc32(view[12:32]) == start_crc
        next_offset, next_size, next_crc = struct.unpack_from("<QQI", view, 12)
        at = 32 + next_offset
        sh["header_offset"], sh["header_bytes"] = at, next_size
        out["header_offset"], out["header_bytes"] = at, next_size
        if next_size and at + next_size <= len(view):
            searched = min(next_size, max_metadata)
            if not touch(fd, at, at + searched):
                header_cut, searched = stop_cause(), 0
            elif searched < next_size:
                sh["search_truncated"] = True
                sh["search_note"] = "the header is %d bytes: only the first %d (max_metadata_bytes) were searched" % (next_size, searched)
            else:
                crc = 0
                for chunk_at in range(at, at + next_size, 1 << 20):
                    crc = zlib.crc32(view[chunk_at:min(chunk_at + (1 << 20), at + next_size)], crc)
                sh["header_crc_ok"] = crc == next_crc
        else:
            at = 0
            sh["problem"] = ("the start header places the header past the end of the file: the archive is truncated "
                             "or was carved short")
            out["header_problem"] = sh["problem"]
    hint = {}
    if searched:
        kind = view[at]
        has_aes = view.find(SEVENZIP_AES, at, at + searched) >= 0
        if kind == 0x01:
            hint["header_kind"] = "plain"
            hint["data_encryption_coder_in_header"] = has_aes
        elif kind == 0x17:
            hint["header_kind"] = "encoded"
            hint["header_encrypted"] = has_aes
            hint["basis"] = ("the AES coder id appears in the encoded header's own coder list: a byte search, not a "
                             "parse of the coder graph")
        else:
            hint["header_kind"] = "unknown (0x%02x)" % kind
    if header_cut:
        out["header_read_cut"] = "%s before the header was read" % header_cut
        listing, members = {"status": "not attempted", "reason": out["header_read_cut"]}, None
    else:
        listing, members = list_with_7z(path, limit)
    out["listing"] = listing
    status = listing["status"]
    if members is not None:
        page = members.finish()
        out["members"] = members.page
        out["member_count"] = page["matched"]
        out.update(page)
        seen = listing["members_seen"]
        out["names_readable"] = True
        out["header_encrypted"] = False
        if seen["encrypted"]:
            out["payload_encrypted"] = True
        elif seen["members"] and not seen["flag_missing"]:
            out["payload_encrypted"] = False
        else:
            out["payload_encrypted"] = None
        out["protected"] = out["payload_encrypted"]
        out["encrypted_members"] = seen["encrypted"]
        out["protection"] = "7z's listing (each member's Encrypted flag)"
    elif status == "header_encrypted":
        out["names_readable"] = False
        out["header_encrypted"] = True
        out["payload_encrypted"] = None
        out["protected"] = True
        out["protection"] = "7z cannot open the archive without a password"
    else:
        out["protection"] = "heuristic: 7z gave no listing (%s)" % status
        out["hints"] = hint
        strings = SealedPage("archive_probe", [os.path.realpath(path), "7z header strings (hint)"], limit)
        # Both patterns are walked lazily over the mapped header and merged by
        # offset, straight into the paging file: no match is collected first.
        ascii_runs = ((m.start(), m.group().decode("ascii", "replace")) for m in ASCII_RUN.finditer(view, at, at + searched))
        wide_runs = ((m.start(), m.group().decode("utf-16-le", "replace")) for m in WIDE_RUN.finditer(view, at, at + searched))
        cut = False
        if searched:
            for _start, text in heapq.merge(ascii_runs, wide_runs, key=lambda found: found[0]):
                if stop_wanted():       # every string: one of them may take a moment to judge
                    cut = True
                    break
                strings.add(withhold(text))
        page = strings.finish()
        out["header_strings_hint"] = strings.page
        out["header_strings_hint_count"] = page["matched"]
        out["header_strings_hint_page"] = page
        if cut:
            out["header_strings_cut"] = "%s: the strings after the %d listed were not read" % (stop_cause(), page["matched"])
        out["header_strings_note"] = ("Printable strings in the header region, not a member list: they include "
                                      "internal names and can miss names. Treat them as a hint.")
    out["next_reader"] = "7z l -slt on a complete copy of every volume of the archive" if status != "listed" else None
    out["not_determined"] = ["whether an encrypted member's data is intact", "the member names where the header is encrypted"] \
        if status in ("header_encrypted",) else ["whether an encrypted member's data is intact or openable"]
    if status == "listed":
        out["status"], out["status_basis"] = "complete", "7z listed the archive without warnings and every member's flag was read"
    elif status == "header_encrypted":
        out["status"], out["status_basis"] = "complete", "7z reports that the archive's header is encrypted: the names need the password, which is the finding"
    else:
        out["status"] = "partial"
        out["status_basis"] = "7z's listing was %s (%s): the member list is %s" % (status, listing.get("reason", "see listing"), "partial or absent")
    return out


def probe_rar(blob):
    version = 5 if bytes(blob[:8]) == b"Rar!\x1a\x07\x01\x00" else 4
    return {"container": "RAR%d" % version, "protected": None,
            "protection": "not determined: this tool identifies the format only",
            "listing": "not attempted", "status": "partial",
            "status_basis": "the format was identified; whether its data or names are encrypted is not determined by this tool",
            "next_reader": "a RAR-capable reader (7-Zip or unrar), on every volume; none is run here",
            "not_determined": ["whether the data is encrypted", "whether the file names are encrypted", "the member list"],
            "note": "A RAR may encrypt its data, and in RAR5 its names as well; this tool reads neither."}


def markers(blob, fd, needle):
    """Offsets of a byte string in the whole file: the first few, and the count (capped). Searched a window at a time, each read first (touch)."""
    offsets, count, capped, pos, size = [], 0, False, 0, len(blob)
    while pos < size and not capped:
        end = min(size, pos + WINDOW)
        if not touch(fd, pos, end):
            SEARCH["cut"] = True
            break
        stop_at = min(size, end + len(needle) - 1)       # a match that starts in this window may end in the next
        at = blob.find(needle, pos, stop_at)
        while 0 <= at < end:
            if count >= MARKER_COUNT_CAP:
                capped = True
                break
            count += 1
            if len(offsets) < MARKER_OFFSETS:
                offsets.append(at)
            at = blob.find(needle, at + 1, stop_at)
        pos = end
    return {"found": count > 0, "count": count, "count_capped": capped, "first_offsets": offsets}


def first_match(blob, fd, pattern):
    """The first match of a compiled pattern in the whole file (None when there is none or the search was cut), a window at a time, each read first."""
    pos, size = 0, len(blob)
    while pos < size:
        end = min(size, pos + WINDOW)
        if not touch(fd, pos, end):
            SEARCH["cut"] = True
            return None
        m = pattern.search(blob, pos, min(size, end + 128))      # a match across the window's end is found from this window
        if m is not None and m.start() < end:
            return m
        pos = end
    return None


def whole_search(blob):
    """What a byte search over a PDF or an OLE file covered: all of it, bounded only by the tool's timeout."""
    return {"bytes_searched": len(blob), "search_complete": not SEARCH["cut"],
            "search_note": "the whole file was searched, in a linear pass per marker: max_metadata_bytes does not bound "
                           "it (a PDF's marker sits in its trailer, at the end), and a file too large to search within "
                           "the tool's own time limit (max_seconds) is reported as cut, with the markers found so far"}


def heuristic_status(out, what):
    out["status"] = "partial"
    out["status_basis"] = ("%s; a byte search is a heuristic, so whether the document is encrypted is not determined" % what) if not SEARCH["cut"] \
        else "the search was cut at the tool's time limit or by a signal, and a byte search is a heuristic anyway"
    return out


PDF_V, PDF_R, PDF_P = re.compile(rb"/V\s+(\d+)"), re.compile(rb"/R\s+(\d+)"), re.compile(rb"/P\s+(-?\d+)")


def probe_pdf(blob, fd):
    encrypt = markers(blob, fd, b"/Encrypt")
    out = {"container": "PDF", "protected": None, "protection": "heuristic: a byte search for the /Encrypt marker",
           "encrypt_marker": encrypt,
           "next_reader": NEXT_DOCUMENT_READER,
           "not_determined": ["whether the file's current trailer points at an encryption dictionary (a marker may "
                              "belong to an earlier revision or to unrelated text)",
                              "whether an opening (user) password is needed, or an empty one opens it",
                              "the permission restrictions (a separate setting from the opening password)",
                              "the security handler and its revision"]}
    if encrypt["found"] and not SEARCH["cut"]:
        version, revision, permissions = (first_match(blob, fd, PDF_V), first_match(blob, fd, PDF_R), first_match(blob, fd, PDF_P))
        out["unresolved_hints"] = {
            "v": int(version.group(1)) if version else None, "r": int(revision.group(1)) if revision else None,
            "p": int(permissions.group(1)) if permissions else None,
            "note": "the first /V, /R and /P anywhere in the file, not read through the trailer: they may belong to "
                    "another object or revision"}
    out.update(whole_search(blob))
    out["note"] = ("A PDF can be encrypted and still open with an empty user password; encryption, the opening password "
                   "and the permission restrictions are three separate facts, and none is read here.")
    return heuristic_status(out, "the file was searched for the /Encrypt marker")


def probe_ole(blob, fd):
    wanted = [("EncryptionInfo", "an Office 2007-and-later encrypted document's stream"),
              ("EncryptedPackage", "an Office 2007-and-later encrypted document's stream"),
              ("DataSpaces", "the storage that records an encrypted package's transforms")]
    found = []
    for name, meaning in wanted:
        for encoding, needle in (("UTF-16LE", name.encode("utf-16-le")), ("ASCII", name.encode("ascii"))):
            m = markers(blob, fd, needle)
            if m["found"]:
                found.append({"name": name, "encoding": encoding, "meaning": meaning, **m})
    out = {**whole_search(blob), "container": "OLE compound file", "protected": None,
           "protection": "heuristic: a byte search for stream names that mark an encrypted OOXML package",
           "markers_found": found, "marker_names_searched": [n for n, _ in wanted],
           "next_reader": NEXT_DOCUMENT_READER,
           "not_determined": ["whether the document is encrypted: binary Word, Excel and PowerPoint files record "
                              "their encryption inside the document's own stream, under no marker searched for here",
                              "which scheme and key derivation it uses",
                              "whether a marker is a live directory entry or text inside a stream",
                              "editing restrictions and rights management, which are not the opening password"],
           "note": "No marker found does not mean the document is not encrypted."}
    return heuristic_status(out, "the file was searched for the stream names of an encrypted package")


def last_word(signum):
    interrupted_answer(signum, path=PATH_SHOWN[0])


PATH_SHOWN = ["(not read yet)"]


def kill_active():
    for proc in list(ACTIVE):
        kill_tree(proc)


def main():
    install_stop(last_word, cooperative=False)
    STOP["cleanup"].append(kill_active)
    try:
        args = json.load(sys.stdin)
    except ValueError as exc:
        fail("arguments are not valid JSON", reason=withhold(str(exc)))
    if not isinstance(args, dict):
        fail("arguments must be a JSON object")
    path = args.get("path")
    if not isinstance(path, str) or not path:
        fail("path is required: an archive or a document")
    PATH_SHOWN[0] = shown(path)
    if os.path.isdir(path):
        fail("path is a directory, not a file: name the archive inside it", path=shown(path))
    if not os.path.isfile(path):
        fail("no such file", path=shown(path))
    limit = args.get("limit", 200)
    if not isinstance(limit, int) or isinstance(limit, bool) or limit < 1:
        fail("limit must be a positive integer")
    max_metadata = args.get("max_metadata_bytes", MAX_METADATA_DEFAULT)
    if not isinstance(max_metadata, int) or isinstance(max_metadata, bool) or max_metadata < 4096:
        fail("max_metadata_bytes must be an integer of at least 4096")
    seconds = args.get("max_seconds", DEFAULT_SECONDS)
    if not isinstance(seconds, int) or isinstance(seconds, bool) or not 1 <= seconds <= MAX_SECONDS:
        fail("max_seconds must be an integer from 1 to %d (the tool's own time limit; the manifest allows 120)" % MAX_SECONDS)
    set_deadline(seconds)

    try:
        size = os.path.getsize(path)
        body = None
        with open(path, "rb") as fh:
            head = fh.read(8)
            if head[:6] == b"7z\xbc\xaf\x27\x1c" or head[:4] == b"Rar!" or head[:5] == b"%PDF-" \
                    or head == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":
                # The whole file, mapped rather than read: the part that decides a
                # PDF is usually its trailer, and a 7-Zip header sits at the end.
                if size == 0:
                    fail("the file is empty", path=shown(path))
                # Every part of the mapping is read through the descriptor before it is used (touch), see there.
                with mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_READ) as view:
                    if head[:6] == b"7z\xbc\xaf\x27\x1c":
                        body = probe_7z(view, fh.fileno(), path, limit, max_metadata)
                    elif head[:4] == b"Rar!":
                        body = probe_rar(view)
                    elif head[:5] == b"%PDF-":
                        body = probe_pdf(view, fh.fileno())
                    else:
                        body = probe_ole(view, fh.fileno())
        # A ZIP is recognised from its own bytes (a local header or an End record), never from a library's yes or no.
        if body is None and (head[:4] in (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08") or read_eocd(path, size) is not None):
            body = probe_zip(path, size, limit, max_metadata)
    except OSError as exc:
        fail("the file could not be read: %s" % describe(exc), path=shown(path))
    if body is None:
        fail("this is not a container this tool reads", path=shown(path), bytes=size,
             reads=["ZIP (found from its end, so empty and self-extracting archives count)", "7-Zip", "RAR", "PDF",
                    "OLE compound file"],
             next_reader="crypto_id names other schemes from the first bytes")

    answer = {
        "path": shown(path), "bytes": size, "parser": PARSER, "max_metadata_bytes": max_metadata, "max_seconds": seconds, **body,
        "names_withheld": NAMES["strings"],
        "reminder": "Whether the member names are readable and whether the data is encrypted are two findings; report "
                    "both. A list of names shows the names the container records: not that the contents are what the "
                    "names suggest, that anything was copied, or where it went.",
    }
    if NAMES["strings"]:
        answer["names_note"] = ("A part of a name, path or header string shaped like an identifier or a secret is withheld from every "
                                "string in this answer and in the files it names; the part is replaced by a marker, the rest of the name "
                                "is shown. Withholding is by shape: an identifier of seven characters or fewer, or of another shape, is printed.")
    if stop_wanted() and body.get("status") == "complete":
        answer["status"], answer["status_basis"] = "partial", "%s before the answer was complete" % stop_cause()
    sealed = seal(answer)
    if NAMES["replaced"]:
        sealed["output_check"] = {"replaced": NAMES["replaced"], "note": "a string the first layer let through was replaced by the output check"}
        sealed["status"] = "partial"
        sealed["status_basis"] = "%s; %d string(s) were replaced by the output check" % (sealed.get("status_basis", ""), NAMES["replaced"])
    emit(sealed)


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except Exception as exc:  # never an empty or clean answer for a failure, and never a traceback
        fail("unexpected failure: %s: %s" % (type(exc).__name__, withhold(str(exc))))
