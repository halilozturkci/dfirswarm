#!/usr/bin/env python3
"""Survey an extracted tree for files that look like ransomware's work, and say exactly what was and was not looked at.

This is a SURVEY. It names candidates by two heuristics and measures entropy in a few
windows; it does not measure how much of any file was encrypted, whether a file
survives whole, who the family is, or when anything ran. What it does:

  * walks the tree in print order (directories and names ordered by the text the answer prints for
    them, names that are withheld in an order drawn afresh each run), follows no link, reads no file that is not a regular
    file, and puts every entry it visited, skipped or could not read into a census;
  * names a file a CANDIDATE when its name carries an extension after a known one
    ("report.docx.locked") or when the first 64 KiB of the file reads at 7.5 bits per
    byte or more. A compressed archive reads the same way, so a candidate is a lead;
  * keeps what it could not measure out of the files that matched nothing: a file of
    4096 bytes or less has no entropy measurement (`unmeasured`), a file it could not
    open or read is `read_failed`, and a file not read because the read budget was
    spent is `unmeasured` with that reason. `noncandidate` means only "did not meet
    either heuristic": it is no statement about the file's content;
  * profiles the first `sample` candidates of more than 4096 bytes: entropy of three
    64 KiB windows (head, middle, end) with their offsets and lengths, and the last
    `tail_bytes` bytes. Windows can overlap in a small file, and intermittent
    encryption can fall between them;
  * counts modification times by hour twice, for every regular file and for the
    candidates. The clock is the filesystem's mtime as collected, which an extraction
    or a copy can change; it is not an execution time of anything;
  * reports what the sampled tails share as an observation pending a reference match;
  * prints a path only through shown() (the same rule ransom_note_scan uses): every
    directory component, and the name of a file that is named like a note
    (ransom_note_scan's pattern), is withheld when it holds a token shaped like an
    identifier, since some families put the victim's identifier there; the count is
    `paths_withheld`. The name of any other file, an encrypted file's included, is
    printed as it is: it is the evidence. The shape is a guess, so a harmless name can
    be withheld and an identifier of another shape is printed.

Nothing is cut: the whole census, every candidate and every table longer than `limit`
are written as JSON Lines (under $OUT/tool-output in a job, else work/<agent>/tool-output)
and named in the answer; the census ends with a receipt row, so a file without one is
partial. A result file that is already there is never replaced by another result: the
new one takes the next free name and the answer names it. `max_seconds` is the tool's own
clock (below the manifest's timeout): when it runs out the walk stops, what was counted is
written, and the answer says `partial` and how much of the tree was not examined. A stop
signal (SIGTERM, SIGINT, SIGHUP) ends the tool with one JSON answer, status `failed` and
`interrupted`, exit code 128 + the signal, after removing the files it was still writing.
Exit code 0 means the survey ran; `status` and `complete` say whether it covered the tree.
"""
import builtins
import collections
import datetime
import errno
import functools
import hashlib
import json
import math
import os
import re
import stat
import sys
import tempfile
import unicodedata
from pathlib import Path

PARSER = "encrypted_survey/3"
WINDOW = 65536
SMALL = 4096                 # a file of at most this many bytes has no entropy measurement
HEAD_THRESHOLD = 7.5         # bits per byte in the head window
END_LOW = 6.5                # bits per byte below which an end window is called low
DEFAULT_SAMPLE, MAX_SAMPLE = 200, 10000
DEFAULT_TAIL, MAX_TAIL = 32, 1024
DEFAULT_BUDGET, MIN_BUDGET = 4 << 30, 4096
DEFAULT_SECONDS, MAX_SECONDS = 780, 840    # the manifest allows 900: the walk stops here so that what it has is written and sealed
DEFAULT_EXCLUDE_TOP = ["proc", "sys", "dev"]
EXT_CAP = 50000              # distinct appended extensions held in memory; the census holds every one
HOUR_CAP = 100000            # distinct hour buckets held in memory per histogram

# Extensions that name what a file was before something was appended to its name. A name that
# keeps one of them and ends in another is a candidate: "report.docx.locked", "report.docx.id[AB12].locked".
KNOWN = {"jpg", "jpeg", "png", "gif", "bmp", "tif", "tiff", "webp", "heic", "heif", "psd",
         "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "rtf", "odt", "ods", "odp", "epub", "msg", "eml",
         "pst", "ost", "txt", "csv", "xml", "json", "html", "md", "log", "ini", "cfg", "conf", "yml", "yaml",
         "zip", "gz", "tgz", "bz2", "xz", "zst", "7z", "rar", "tar", "jar", "apk",
         "mp4", "mp3", "mkv", "avi", "mov", "wmv", "flac", "ogg", "wav", "m4a", "aac",
         "exe", "dll", "sys", "dat", "sql", "bak", "db", "mdb", "accdb",
         "vhd", "vhdx", "vmdk", "iso", "img", "py", "js", "c", "cpp", "h", "java", "php"}
# Formats that are normally compressed or packed: a high-entropy head is what they look like
# whole, so entropy alone is the weakest reason to call one of them a candidate.
COMPRESSED_FORMATS = {"jpg", "jpeg", "png", "gif", "webp", "heic", "heif", "pdf", "docx", "xlsx", "pptx",
                      "odt", "ods", "odp", "epub", "zip", "gz", "tgz", "bz2", "xz", "zst", "7z", "rar", "jar", "apk",
                      "mp4", "mp3", "mkv", "avi", "mov", "wmv", "flac", "ogg", "m4a", "aac"}
# The pattern ransom_note_scan uses to take a file for a note by its name, so that the two tools
# agree on which names are note names.
NAME_HINTS = re.compile(
    r"(readme|read_me|decrypt|restore|recover|unlock|how[\W_]*to|ransom|help[\W_]*|"
    r"your[\W_]*files|instruction|_note|!!!)", re.I)

# Lossless paging (the same in every library tool that pages): the page an
# agent reads stays small, and when there are more rows the whole result is
# written as JSON Lines under work/<agent>/tool-output and named.
import hashlib


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
                     "work/<your id>/ directory; in a job it is $OUT." % (self.total, self.shown, describe(exc)),
            "status": "failed",
            "status_basis": "the tool stopped with an error (see error); the whole result could not be kept, so there is no answer",
        }) + "\n")
        _sys.exit(1)

    def _write(self, row: object) -> None:
        assert self._out is not None
        # ASCII only: U+2028, U+0085, a bidi override and a lone surrogate (a file name that is not UTF-8) are escaped, lose nothing, and a
        # line of the file is always a row.
        text = json.dumps(row, ensure_ascii=True, default=str)
        try:
            self._out.write(text)
            self._out.write("\n")
        except OSError as exc:
            self._cannot_write(exc)

    def add(self, row: object, evidence: str | None = None) -> object:
        """Keep a row: read back by the backstop first (`evidence` is the name of a file printed as it is on purpose), then paged. Returns
        the row as kept."""
        row = seal_row(row, evidence)
        self.total += 1
        if len(self.page) < self.limit:
            self.page.append(row)
            return row
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
        return row

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


# BEGIN SHARED STOP
# The same text is in regkv, shellbags and amcache_apps (held equal by a windows-forensics test). SIGTERM, SIGINT and SIGHUP end the tool with JSON (status
# interrupted, exit 128 + the signal) and remove the temporary file a page was writing; the tool's own clock (set_deadline) is below the manifest's.
import signal
import time

STOP = {"last_word": None, "deadline": None}


def set_deadline(seconds):
    STOP["deadline"] = time.monotonic() + seconds


def out_of_time():
    return STOP["deadline"] is not None and time.monotonic() > STOP["deadline"]


def _on_signal(signum, _frame):
    for page in list(PAGES):
        tmp = getattr(page, "_tmp", None)
        if tmp is not None:
            try:
                os.unlink(tmp)
            except OSError:
                pass
    last_word = STOP["last_word"]
    if last_word:
        try:
            last_word(signum)
        except Exception:  # noqa: BLE001 - a last word is best effort
            pass
    os._exit(128 + signum)


def install_signal_handlers(last_word=None):
    STOP["last_word"] = last_word
    for signum in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(signum, _on_signal)


def interrupted_answer(signum, **extra):
    print(json.dumps({"error": "stopped by signal %d before the answer was complete" % signum, "status": "interrupted",
                      "status_basis": "the tool was stopped by signal %d; nothing it had read is an answer" % signum,
                      "signal": signum, **extra}), flush=True)
# END SHARED STOP

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
# The same text is in encrypted_survey and ransom_note_scan, so that the two tools judge a name alike (a ransomware-response test holds
# the copies equal). A path is printed only through shown(): every component is judged, and no directory above a file is exempt.
# Everything derived from a name that is withheld (an extension, a stem, a length, the place of the name among its siblings) is withheld
# with it: a name that is withheld is replaced by one constant marker, and the order of a listing never follows the text that was withheld.
WITHHELD = "<identifier-shaped name withheld>"
WITHHELD_PATHS = [0]              # printed paths that had a component withheld (one per call of shown)
_IDRUN = re.compile(r"[A-Za-z0-9]{8,}")
_WORDY = re.compile(r"[A-Z]?[a-z]+(?:[A-Z][a-z]+)*|[A-Z]+")
_PAIR_SEPARATORS = re.compile(r"[^0-9A-Za-z]")
_DIGIT_GROUPS = re.compile(r"(?<![0-9])[0-9]{3,}(?:[ ,][0-9]{3,})+(?![0-9])")
HEX_DIGITS = frozenset("0123456789abcdefABCDEF")
SINGLE_CASE_RUN = 16              # a run of letters of one case is a word below this many letters, a random run from here on
HEX_PAIRS = 8                     # this many pairs of hex digits joined by one separator are a byte string
# Directory names every Windows, Linux and ESXi host has, whose letters and digits would otherwise be taken for an identifier, and the names
# of the exceptions Python raises (the tools print the type of an error: IsADirectoryError reads as letters that are not words). A component
# is printed as it is when it is one of these, whole and in any case.
WELL_KNOWN = frozenset((
    "system32", "syswow64", "inetcache", "inetcookies", "inethistory", "msocache", "psreadline", "framework", "framework64",
    "sqlserver", "gpucache", "dawnwebgpucache", "dawngraphitecache", "grshadercache", "indexeddb", "overlay2", "datastore1")
) | frozenset(name.lower() for name, value in vars(builtins).items() if isinstance(value, type) and issubclass(value, BaseException))


# The characters whose NFKC form holds a slash (a full-width solidus, the "a/c", "a/s", "c/o" and "c/u" signs) each read as one backslash, a
# separator that is not a slash: a path is split at the real slashes only, and a folded one would cut a run of pairs into pieces of one.
_SLASH_LIKE = dict.fromkeys((0x2100, 0x2101, 0x2105, 0x2106, 0xFF0F), "\\")
# Characters that show nothing and are not format characters: a combining grapheme joiner, variation selectors, Mongolian free variation
# selectors, hangul and khmer fillers, a braille blank, tag and musical controls, the other default-ignorable code points.
_INVISIBLE = re.compile("[\u00ad\u034f\u061c\u115f\u1160\u17b4\u17b5\u180b-\u180f\u200b-\u200f\u202a-\u202e\u2060-\u206f\u2800\u3164"
                        "\ufe00-\ufe0f\ufeff\uffa0\ufff0-\ufff8\U0001bca0-\U0001bca3\U0001d173-\U0001d17a\U000e0000-\U000e0fff]")


def _unseen(ch):
    """Whether a non-ASCII character shows nothing of its own: a format character, a combining mark, a default-ignorable code point."""
    return unicodedata.category(ch) in ("Cf", "Mn", "Mc", "Me") or _INVISIBLE.match(ch) is not None


def fold(name):
    """The name as the rule reads it: NFKC (a full-width letter or digit is the ASCII one; a full-width solidus is a separator, not a
    slash), every decimal digit of any script as its ASCII digit, and nothing that shows nothing: no format character, no combining mark
    (taken off the letter it sits on before the two are composed), no default-ignorable code point (a zero-width space, a variation
    selector, a filler cannot split a token)."""
    if name.isascii():
        return name
    out = []
    for ch in unicodedata.normalize("NFKC", "".join(c for c in name.translate(_SLASH_LIKE) if c.isascii() or not _unseen(c))):
        if ord(ch) < 128:
            out.append(ch)
        elif unicodedata.category(ch) == "Nd":
            out.append(str(unicodedata.decimal(ch)))
        elif not _unseen(ch):
            out.append(ch)
    return "".join(out)


def _hex_pairs(text):
    """Whether HEX_PAIRS or more pairs of hex digits follow each other, one separator between two. A separator is any character that is not
    an ASCII letter or a digit (the pairs of `id[aa-bb-...-hh]`, `key=aa:bb:...` and `(aa.bb...)` are found: a neighbour of the run that is
    not a letter or a digit does not hide a pair at its end), and only a letter or a digit glued to a pair makes it no pair. A run does not
    cross a slash: a path is read one component at a time (a full-width solidus is not a slash: fold turns it into a separator)."""
    for part in text.split("/"):
        run = 0
        for piece in _PAIR_SEPARATORS.split(part):
            if len(piece) == 2 and piece[0] in HEX_DIGITS and piece[1] in HEX_DIGITS:
                run += 1
                if run >= HEX_PAIRS:
                    return True
            else:
                run = 0
    return False


def _digit_groups(text):
    """Whether groups of three or more digits, joined by a space or a comma, hold ten or more digits together."""
    return any(sum(c.isdigit() for c in m.group(0)) >= 10 for m in _DIGIT_GROUPS.finditer(text))


def shaped(name):
    """Whether a name holds a token shaped like an identifier. The name is folded first (fold). A token is a run of 8 or more ASCII
    letters and digits. It is identifier-shaped when it holds both letters and digits, or is 10 or more digits, or is letters only and is
    not one word, one capitalised word, several capitalised words or all capitals, or is 16 or more letters of one case. So are 8 or more
    pairs of hex digits joined by one separator (any character that is not a letter, a digit or a slash: a colon, a dash, a dot, an underscore,
    a space, a bracket, an equals sign; a letter or a digit glued to a pair at an end of the run makes that pair no pair), and groups of
    digits joined by a space or a comma that hold 10 digits or more. The rule is a shape: a longer or different separator, a different
    grouping and other scripts are not covered (see the manifests)."""
    text = fold(name)
    for m in _IDRUN.finditer(text):
        token = m.group(0)
        if token.isdigit():
            if len(token) >= 10:
                return True
        elif any(c.isdigit() for c in token):
            return True
        elif not _WORDY.fullmatch(token):
            return True
        elif len(token) >= SINGLE_CASE_RUN and (token.islower() or token.isupper()):
            return True
    return len(text) >= 23 and _hex_pairs(text) or len(text) >= 11 and _digit_groups(text)


@functools.lru_cache(maxsize=65536)
def _judge(part):
    """What to print in place of one path component, or None to print it as it is. A component that is judged is withheld whole, by
    one marker that says nothing of its length or its shape."""
    if part.lower() in WELL_KNOWN:
        return None
    if shaped(part):
        return WITHHELD
    return WITHHELD if scrub(part, "names") != part else None


def shown(path, values=(), keep_last=False, count=True):
    """A path as it may be printed: every component that could carry an identifier is withheld.

    A component is withheld when it holds a token shaped like an identifier (shaped), when the shared withholding rules above find a
    token, a key or user-info in it, or when it contains a value the note held (case-insensitive, 8 characters or more). The same rule
    applies to every path a tool prints, so a name is never hidden on one line and printed on the next; a harmless name can be withheld
    with it, and the directory can be listed. keep_last leaves the final component as it is (a name that is itself the evidence).
    """
    if not isinstance(path, str):
        return path
    parts = path.split("/")
    last = len(parts) - 1
    lows = [v.lower() for v in values if len(v) >= 8]
    changed = False
    for i, part in enumerate(parts):
        if not part or (keep_last and i == last):
            continue
        replaced = _judge(part)
        if replaced is None and lows:
            low = part.lower()
            if any(v in low for v in lows):
                replaced = WITHHELD
        if replaced is not None:
            parts[i] = replaced
            changed = True
    if changed and count:
        WITHHELD_PATHS[0] += 1
    return "/".join(parts)


_ORDER_SALT = os.urandom(16)


def print_order(entries, judged, hidden=None):
    """The directory entries in the order an answer prints them: by the text printed for each (the marker for a name that is judged
    and withheld, the name itself otherwise; `judged(entry)` says whether the answer prints the entry's name through the judge;
    `hidden(entry)`, when given, says that a name the first rule lets through is withheld all the same, because the note beneath it holds
    its value: it sorts as the marker does), and the entries that print alike in an order drawn afresh every run (a keyed hash of the whole
    path, the directory above included, under a salt of this run: the same name in two directories has two unrelated ranks). The rank of a
    withheld name among its siblings, the order a directory lists them in and the inode never show in what an answer lists, in the
    order of its rows, in the numbers it hands out or in which entries a limit keeps."""
    texts = []
    for entry in entries:
        name = entry.name
        try:
            if hidden is not None and hidden(entry):
                texts.append(WITHHELD)
            else:
                texts.append((_judge(name) or name) if judged(entry) else name)
        except OSError:
            texts.append(_judge(name) or name)
    order = sorted(range(len(entries)), key=texts.__getitem__)
    out, i = [], 0
    while i < len(order):
        j = i + 1
        while j < len(order) and texts[order[j]] == texts[order[i]]:
            j += 1
        group = order[i:j]
        if len(group) > 1:
            group.sort(key=lambda n: (hashlib.blake2b(entries[n].path.encode("utf-8", "surrogatepass"), key=_ORDER_SALT, digest_size=8).digest(), n))
        out.extend(group)
        i = j
    return [entries[n] for n in out]
# END SHARED NAMES


# BEGIN SHARED BACKSTOP
# The same text is in encrypted_survey and ransom_note_scan (a ransomware-response test holds the copies equal). Every row a page or the census
# keeps and the answer itself pass through here on their way out, whatever the code that made them did: a second check, written apart from
# shown() (it reads a string whole, not component by component, and calls neither the judge, scrub nor any call site's decision), that
# replaces a string holding an identifier-shaped text by a marker, counts it, and makes a complete answer partial. The one exception is on
# purpose: the name of a file that is not named like a note is evidence and is printed as it is (the caller says so with `evidence`, and the
# check refuses that claim for a name that is note-named). Content that is hex by nature (a digest, a tail) is passed by its key.
BOUNDARY = {"replaced": 0, "by": {}, "where": [], "not_listed": 0}
OWN_NAMES = set()                 # the names of the files this run wrote (their digest is the name of the root and of the table)
FREE_KEYS = frozenset(("sha256", "tail_hex", "suffix_hex"))
PROSE_KEYS = frozenset(("reason", "status_basis", "partial_reasons"))    # the tool's own sentences: "(4294967296 bytes)" there is a size, not a name
SERIAL_KEYS = frozenset(("note_id", "finding_id", "first_note_id", "duplicate_of"))      # a sequence number this tool counted: N000001, F1000000
_SERIAL = re.compile(r"[NF][0-9]{6,12}")
MAX_REPLACED_LISTED = 20
MAX_JUDGED = 1 << 16
_SUSPECT = re.compile(r"[A-Za-z0-9]{8}|(?:[0-9A-Fa-f]{2}[^0-9A-Za-z/]){4}|[0-9]{3}[ ,][0-9]{3}")
_ALNUM_RUN = re.compile(r"[A-Za-z0-9]+")
_PAIRS = re.compile(r"(?<![0-9A-Za-z])[0-9A-Fa-f]{2}(?:[^0-9A-Za-z/][0-9A-Fa-f]{2}){7}(?![0-9A-Za-z])")
_GROUPS = re.compile(r"(?<![0-9])[0-9]{3,}(?:[ ,][0-9]{3,})+(?![0-9])")


class Sealed(dict):
    """A row that has been through the backstop: it is not read again (its evidence name would not pass without the claim made for it)."""


_FOLDS_TO_SLASH = dict.fromkeys((0x2100, 0x2101, 0x2105, 0x2106, 0xFF0F), "\\")      # NFKC turns these into a slash: not a path separator here
_UNSEEN = re.compile("[\u00ad\u034f\u061c\u115f\u1160\u17b4\u17b5\u180b-\u180f\u200b-\u200f\u202a-\u202e\u2060-\u206f\u2800\u3164"
                     "\ufe00-\ufe0f\ufeff\uffa0\ufff0-\ufff8\U0001bca0-\U0001bca3\U0001d173-\U0001d17a\U000e0000-\U000e0fff]")


def _read_as(text):
    """The string as the check reads it: NFKC (a full-width solidus is a separator, not a slash), decimal digits of any script as ASCII
    digits, nothing that shows nothing (no format character, no combining mark, no default-ignorable code point; a mark is taken off the
    character it sits on before the two are composed into one)."""
    if text.isascii():
        return text
    seen = lambda ch: unicodedata.category(ch) in ("Cf", "Mn", "Mc", "Me") or _UNSEEN.match(ch) is not None     # noqa: E731
    kept = []
    for ch in unicodedata.normalize("NFKC", "".join(c for c in text.translate(_FOLDS_TO_SLASH) if c.isascii() or not seen(c))):
        if ch.isascii():
            kept.append(ch)
        elif unicodedata.category(ch) == "Nd":
            kept.append(str(unicodedata.decimal(ch)))
        elif not seen(ch):
            kept.append(ch)
    return "".join(kept)


@functools.lru_cache(maxsize=65536)
def _why(text, prose=False):
    """The reason a string may not be printed (a fixed sentence, never a part of the string), or None. `prose` is a sentence of the tool's
    own (a reason, a status basis): a number of 10 or more digits followed by " bytes" is a size there and is not read as a name."""
    flat = _read_as(text)
    for found in _ALNUM_RUN.finditer(flat):
        run = found.group()
        size = len(run)
        if size < 8 or run.lower() in WELL_KNOWN:
            continue
        digits = sum(1 for c in run if c.isdigit())
        if digits == size:
            if size >= 10 and not (prose and flat.startswith(" bytes", found.end())):
                return "a long run of digits"
        elif digits:
            return "letters and digits in one run"
        elif run.isupper() or run.islower():
            if size >= 16:
                return "a long run of letters of one case"
        elif any(c.isupper() and not (i + 1 < size and run[i + 1].islower()) for i, c in enumerate(run)):
            return "letters that do not read as words"
    if _PAIRS.search(flat):
        return "pairs of hex digits"
    for m in _GROUPS.finditer(flat):
        if sum(c.isdigit() for c in m.group(0)) >= 10:
            return "groups of digits"
    return None


_CLEAN = set()                    # short strings already found clean (keys, repeated words): not read again


def _refuse(text, evidence, prose=False):
    """Why this string may not be printed, or None. `prose` is set for the tool's own sentences (see _why)."""
    size = len(text)
    if size < 8 or text in _CLEAN or text in OWN_NAMES:
        return None
    if size > MAX_JUDGED:
        return "a string too long to check"
    if evidence and not NAME_HINTS.search(evidence):
        if text.lower() in evidence.lower():              # the name itself, or a piece of it (its extension)
            return None
        if text.endswith("/" + evidence):                 # a path whose last component is the evidence
            text = text[:-len(evidence) - 1]
            size = len(text)
            if size < 8:
                return None
    why = None if text.isascii() and not _SUSPECT.search(text) else _why(text, prose)
    if why is None and not prose and size <= 64 and len(_CLEAN) < 20000:
        _CLEAN.add(text)
    return why


def _place(where):
    """The place of a string as text: the keys that are plain words and the indexes above it, never a key that came from a name (a key is a
    word only when it is also one to the second check: a key of letters and digits is not printed, whatever it looks like)."""
    parts = []
    while where is not None:
        where, label = where
        word = not isinstance(label, int) and re.fullmatch(r"[a-z][a-z_0-9]{0,40}", str(label)) and _why(str(label)) is None
        parts.append(label if isinstance(label, int) or word else "*")
    return "/" + "/".join(str(p) for p in reversed(parts))


def _replaced(why, where):
    BOUNDARY["replaced"] += 1
    BOUNDARY["by"][why] = BOUNDARY["by"].get(why, 0) + 1
    if len(BOUNDARY["where"]) < MAX_REPLACED_LISTED:
        BOUNDARY["where"].append({"at": _place(where), "check": why})
    else:
        BOUNDARY["not_listed"] += 1
    return "<withheld at the output: %s>" % why


def _read_back(value, where, key, evidence):
    """`value` with every string checked; the same object when nothing was replaced."""
    if isinstance(value, Sealed):
        return value
    if isinstance(value, str):
        if len(value) < 8 or key in FREE_KEYS or (key in SERIAL_KEYS and _SERIAL.fullmatch(value)):
            return value
        why = _refuse(value, evidence, key in PROSE_KEYS)
        return _replaced(why, where) if why else value
    if isinstance(value, dict):
        pairs, changed = [], False
        for k, v in value.items():
            nk = _read_back(k, (where, "(key)"), None, None) if isinstance(k, str) and len(k) >= 8 else k
            if isinstance(v, (str, dict, list, tuple)):
                nv = _read_back(v, (where, k if nk is k else "(key)"), k if isinstance(k, str) else None, evidence)
            else:
                nv = v
            changed = changed or nk is not k or nv is not v
            pairs.append((nk, nv))
        if not changed:
            return value
        out = {}
        for nk, nv in pairs:
            while nk in out:
                nk = "%s #" % nk
            out[nk] = nv
        return out
    if isinstance(value, (list, tuple)):
        items = [_read_back(v, (where, i), key, evidence) for i, v in enumerate(value)]
        return value if all(a is b for a, b in zip(items, value)) else items
    return value


def seal_row(row, evidence=None):
    """A row on its way to a page or the census: every string read back. `evidence` is the name of the file the row is about when it is
    printed as it is on purpose (a file that is not named like a note)."""
    if isinstance(row, Sealed):
        return row
    out = _read_back(row, None, None, evidence)
    return Sealed(out) if isinstance(out, dict) else out


def release(doc):
    """The answer: every string that was not read back already is read back now. A complete answer that had a string replaced is partial."""
    out = _read_back(doc, None, None, None)
    if BOUNDARY["replaced"] and isinstance(out, dict):
        note = {"strings_replaced_at_the_output": BOUNDARY["replaced"], "by_check": dict(BOUNDARY["by"]), "replaced_at": list(BOUNDARY["where"]),
                "replaced_not_listed": BOUNDARY["not_listed"],
                "note": "every string of this answer and of the files it names was read back by a second check, written apart from the rule "
                        "that withholds names; a string it found identifier-shaped is replaced by a marker and its place is in replaced_at"}
        merged = {}
        for k, v in out.items():
            merged[k] = v
            if k == "status_basis":
                merged["boundary"] = note
        merged.setdefault("boundary", note)
        if merged.get("status") == "complete":
            merged["status"] = "partial"
            if "complete" in merged:
                merged["complete"] = "partial"
            merged["status_basis"] = "%s; %d strings held an identifier-shaped text that the first rule missed and were replaced at the output (see boundary)" % (
                merged.get("status_basis") or "every entry was visited", BOUNDARY["replaced"])
        out = merged
    return out
# END SHARED BACKSTOP


def output_place(tool, key):
    """Where a whole result is written and how the answer names it: (real path, path as cited)."""
    digest = hashlib.sha256(json.dumps(key, sort_keys=True, default=str).encode("utf-8")).hexdigest()[:16]
    name = f"{tool}-{digest}.jsonl"
    job, out = os.environ.get("JOB_ID"), os.environ.get("OUT")
    if job and out:
        # In a job only $OUT is written, and it is sealed as the job's output.
        return Path(out) / "tool-output" / name, "store/jobs/%s/out/tool-output/%s" % (re.sub(r"[^A-Za-z0-9_.-]", "_", job), name)
    agent = re.sub(r"[^A-Za-z0-9_.-]", "_", os.environ.get("AGENT_ID") or "tool")
    path = Path("work") / agent / "tool-output" / name
    return path, str(path)


class Census:
    """One JSON line per visited entry, then a receipt; written whole or not at all.

    The file is made under a temporary name and placed when the receipt is written, so an
    interrupted survey leaves no file with the census's name: a census that exists is a
    census that ends in its receipt. It is placed without replacing a census already
    there (a rerun with other parameters writes a different census, and the earlier one,
    which may be the larger, stays); the answer names the file that holds this one.
    """

    def __init__(self, key):
        self.path, self.shown = output_place("encrypted_survey-census", key)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd, name = tempfile.mkstemp(dir=self.path.parent, prefix=f".{self.path.name}-")
        self._tmp = Path(name)
        self._out = os.fdopen(fd, "w", encoding="utf-8")
        self.rows = 0
        PAGES.append(self)

    def add(self, row, evidence=None):
        row = seal_row(row, evidence)
        self._out.write(json.dumps(row, ensure_ascii=True, default=str))
        self._out.write("\n")
        self.rows += 1
        return row

    def finish(self, receipt):
        receipt = release({"record": "receipt", "rows": self.rows, **receipt})
        self._out.write(json.dumps(receipt, ensure_ascii=True, default=str))
        self._out.write("\n")
        self._out.flush()
        os.fsync(self._out.fileno())
        self._out.close()
        placed = place_without_replacing(self._tmp, self.path)
        self._tmp = None
        self.path = placed
        self.shown = self.shown[: len(self.shown) - len(Path(self.shown).name)] + placed.name


class NoCensus:
    """Stands in for the census when no file can be made for it: the rows are counted, none is kept."""

    shown = None

    def __init__(self):
        self.rows = 0

    def add(self, row, evidence=None):
        self.rows += 1
        return row

    def finish(self, receipt):
        pass


def fail(message, **extra):
    print(json.dumps(release({"error": message, "status": "failed",
                              "status_basis": "the tool stopped with an error (see error); it produced no survey", **extra})))
    raise SystemExit(1)


def describe(exc):
    """An error without the path it names: type, errno name and the system's own words (never the text of an exception that has none:
    it can name the place of the output)."""
    code = errno.errorcode.get(exc.errno, "") if getattr(exc, "errno", None) else ""
    words = getattr(exc, "strerror", None) or ("no free name for a result file" if str(exc).startswith("no free name") else "no system message")
    return "%s%s: %s" % (type(exc).__name__, " " + code if code else "", words)


def where_it_failed(exc):
    """The line of this tool an unexpected exception was raised on: enough to find it, and no text of the exception (which can name a path)."""
    tb = exc.__traceback__
    line = None
    while tb is not None:
        if tb.tb_frame.f_code.co_filename == __file__:
            line = tb.tb_lineno
        tb = tb.tb_next
    return "line %s of the tool" % line if line else "an unknown line"


PROGRESS = {}


def last_word(signum):
    """What the tool says when a stop signal ends it: one JSON answer, never a clean-looking partial one."""
    print(json.dumps({"error": "stopped by signal %d before the survey was complete" % signum, "status": "failed",
                      "status_basis": "the tool was stopped by signal %d; the census and the tables it was still writing were removed, "
                                      "so nothing it had read is an answer" % signum,
                      "interrupted": True, "signal": signum, "coverage_so_far": PROGRESS.get("coverage")}), flush=True)


def drop_temporary_files():
    """Remove the files a page or the census was still writing (a failure, not a stop signal, ended the tool)."""
    for page in list(PAGES):
        tmp = getattr(page, "_tmp", None)
        if tmp is not None:
            try:
                os.unlink(tmp)
            except OSError:
                pass


EPOCH = datetime.datetime(1970, 1, 1, tzinfo=datetime.timezone.utc)


def iso_utc(ns):
    """A nanosecond count since 1970-01-01 UTC as ISO 8601 (whole microseconds), or None when
    it is outside what a datetime holds: one file's time is one file's problem. The raw count
    is kept beside it wherever it is shown."""
    try:
        when = EPOCH + datetime.timedelta(microseconds=ns // 1000)
    except (OverflowError, ValueError, TypeError):
        return None
    return when.replace(tzinfo=None).isoformat() + "Z"


def entropy_exact(block):
    """Shannon entropy of the bytes of a block, in bits per byte, unrounded: the value every threshold is compared with."""
    if not block:
        return 0.0
    total = len(block)
    bits = -sum((c / total) * math.log2(c / total) for c in collections.Counter(block).values())
    return max(0.0, bits)


def shown_entropy(exact):
    """The entropy as it is printed: three places. A reading of 7.4996 prints as 7.5 and is not at the threshold."""
    return round(exact, 3)


def pread_full(fd, length, offset):
    chunks, got = [], 0
    while got < length:
        data = os.pread(fd, length - got, offset + got)
        if not data:
            break
        chunks.append(data)
        got += len(data)
    return b"".join(chunks)


def window_places(size):
    """Head, middle and end: 64 KiB each, the middle centred on half the size, the end flush with it."""
    return [("head", 0), ("middle", max(0, size // 2 - WINDOW // 2)), ("end", max(0, size - WINDOW))]


def overlap(windows):
    spans = sorted((w["offset"], w["offset"] + w["length"]) for w in windows)
    return any(spans[i][1] > spans[i + 1][0] for i in range(len(spans) - 1))


def name_reasons(name):
    """(reasons, appended extension): a known extension followed by another one is the only name rule.

    Whatever sits between the known extension and the last one (an identifier, an address) is part of
    the pattern: "report.docx.id[AB12CD34].locked" matches. A name that loses its extension, or keeps
    its own, does not.
    """
    parts = name.lower().split(".")
    last = parts[-1] if len(parts) > 1 else ""
    if last and last not in KNOWN and any(p in KNOWN for p in parts[1:-1]):
        return ["appended_extension_after_known_extension"], "." + last
    return [], None


EXT_WITHHELD = "<extension withheld: the name of this file is withheld>"


def evidence_of(name):
    """The name of a file when it is printed as it is on purpose (a file that is not named like a note), else None."""
    return None if NAME_HINTS.search(name) else name


def judged_entry(entry):
    """Whether the answer prints this entry's name through the judge: a directory always, any other entry when it is named like a note."""
    return entry.is_dir(follow_symlinks=False) or bool(NAME_HINTS.search(entry.name))


def display(path):
    """The path as it may be printed. Every directory above the file is judged by shown(); the file's own name is withheld when it
    is named like a note and holds an identifier-shaped token (the name ransom_note_scan withholds), and is otherwise printed as it
    is: a file that is not named like a note is an encrypted file or an ordinary one, and its name is evidence."""
    return shown(path, keep_last=not NAME_HINTS.search(os.path.basename(path)))


def kind_of(mode):
    for test, text in ((stat.S_ISFIFO, "a named pipe"), (stat.S_ISSOCK, "a socket"), (stat.S_ISBLK, "a block device"),
                       (stat.S_ISCHR, "a character device"), (stat.S_ISDIR, "a directory")):
        if test(mode):
            return text
    return "a special file"


def open_regular(path):
    """A descriptor for a regular file, opened without following a link; its fstat comes with it."""
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    fd = os.open(path, flags)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise OSError(errno.EINVAL, "not a regular file (%s)" % kind_of(st.st_mode))
    except OSError:
        os.close(fd)
        raise
    return fd, st


def walk(top, exclude_top, counters, exceptions, skipped, exclusions, census, stopped):
    """Yield (path, lstat) for every regular file under `top`, in print order (print_order), following no link.

    A directory that cannot be listed, an entry that cannot be examined, a link and a file
    that is not a regular file are each counted, listed and put in the census; none is dropped.
    When the tool's own clock runs out the walk ends and `stopped` says how much of the tree it had not reached.
    """
    stack = [(top, True)]
    while stack:
        if out_of_time():
            stopped.update({"entries_not_examined": 0, "directories_not_entered": len(stack)})
            return
        directory, is_top = stack.pop()
        try:
            with os.scandir(directory) as it:
                entries = print_order(list(it), judged_entry)
        except OSError as exc:
            counters["directories_failed"] += 1
            row = {"path": shown(directory), "status": "failed", "what": "directory", "reason": "the directory could not be listed",
                   "error": describe(exc)}
            row = exceptions.add(row)
            census.add({"record": "failed_directory", **row})
            continue
        counters["directories_visited"] += 1
        subdirs = []
        for index, entry in enumerate(entries):
            if out_of_time():
                stopped.update({"entries_not_examined": len(entries) - index, "directories_not_entered": len(stack) + len(subdirs)})
                return
            try:
                if entry.is_symlink():
                    counters["links_not_followed"] += 1
                    row = {"path": display(entry.path), "status": "skipped", "reason": "a symbolic link: not followed, so neither it nor its target was read"}
                    row = skipped.add(row, evidence_of(entry.name))
                    census.add({"record": "skipped", **row}, evidence_of(entry.name))
                    continue
                if entry.is_dir(follow_symlinks=False):
                    if is_top and entry.name in exclude_top:
                        counters["directories_excluded"] += 1
                        row = {"path": shown(entry.path), "reason": "named in exclude_top_level_dirs: a top-level %s directory of a Linux root; "
                                                                     "its contents were not read. Name it as the root to read it" % shown(entry.name, count=False)}
                        exclusions.append(seal_row(row))
                        census.add({"record": "excluded", **row})
                        continue
                    subdirs.append(entry.path)
                    continue
                st = entry.stat(follow_symlinks=False)
            except OSError as exc:
                counters["entries_failed"] += 1
                # what the entry is was not learned: it may be a directory, so its name is judged like one
                row = {"path": shown(entry.path), "status": "failed", "reason": "the entry could not be examined", "error": describe(exc)}
                row = exceptions.add(row)
                census.add({"record": "failed_entry", **row})
                continue
            if not stat.S_ISREG(st.st_mode):
                counters["special_files_skipped"] += 1
                row = {"path": display(entry.path), "status": "skipped", "reason": "not a regular file (%s): not opened" % kind_of(st.st_mode)}
                row = skipped.add(row, evidence_of(entry.name))
                census.add({"record": "skipped", **row}, evidence_of(entry.name))
                continue
            yield entry.path, st
        stack.extend((d, False) for d in reversed(subdirs))


class Budget:
    def __init__(self, total):
        self.total = total
        self.read = 0

    def allows(self, n):
        return self.read + n <= self.total

    def spend(self, n):
        self.read += n


def common_suffix(a, b):
    n, i = min(len(a), len(b)), 0
    while i < n and a[-1 - i] == b[-1 - i]:
        i += 1
    return a[len(a) - i:] if i else b""


KNOWN_PARAMS = {"root", "sample", "tail_bytes", "limit", "read_budget_bytes", "exclude_top_level_dirs", "census", "max_seconds"}


def int_param(args, key, default, low, high=None, why=""):
    value = args.get(key, default)
    if isinstance(value, bool) or not isinstance(value, int):
        fail("%s must be an integer" % key)
    if value < low:
        fail("%s must be at least %d" % (key, low))
    if high is not None and value > high:
        fail("%s must be at most %d%s" % (key, high, why))
    return value


def hour_bucket(iso):
    return iso[:13] + ":00:00Z"


def bump(counter, key, cap, overflow):
    if key in counter or len(counter) < cap:
        counter[key] += 1
    else:
        overflow[0] += 1


def main():
    install_signal_handlers(last_word)
    try:
        args = json.load(sys.stdin)
    except ValueError as exc:
        fail("arguments are not valid JSON", reason=str(exc))
    if not isinstance(args, dict):
        fail("arguments must be a JSON object")
    root = args.get("root")
    if not isinstance(root, str) or not root:
        fail("root is required: a directory to survey")
    if not os.path.isdir(root):
        fail("no such directory", root=shown(root, count=False))
    sample_size = int_param(args, "sample", DEFAULT_SAMPLE, 1, MAX_SAMPLE, " (every profiled candidate is held in the answer's tables)")
    tail_bytes = int_param(args, "tail_bytes", DEFAULT_TAIL, 0, MAX_TAIL)
    limit = int_param(args, "limit", 200, 1)
    budget = Budget(int_param(args, "read_budget_bytes", DEFAULT_BUDGET, MIN_BUDGET))
    max_seconds = int_param(args, "max_seconds", DEFAULT_SECONDS, 1, MAX_SECONDS, " (the tool's own clock; the manifest's timeout is 900)")
    full_census = args.get("census", True)
    if not isinstance(full_census, bool):
        fail("census must be true or false")
    exclude_top = args.get("exclude_top_level_dirs", DEFAULT_EXCLUDE_TOP)
    if not isinstance(exclude_top, list) or not all(isinstance(x, str) and x and "/" not in x for x in exclude_top):
        fail("exclude_top_level_dirs must be a list of directory names (no slash); [] excludes nothing")
    unknown = sorted(k for k in args if k not in KNOWN_PARAMS)
    set_deadline(max_seconds)

    real = os.path.realpath(root)
    shown_root = shown(root)
    census_problem = None
    try:
        census = Census([real, "census"])
    except OSError as exc:
        census, census_problem = NoCensus(), "the census file could not be created (%s): the counts are whole, the per-file rows are not kept" % describe(exc)
    candidates = NoReplacePage("encrypted_survey", [real, "candidates"], limit)
    low_tail = NoReplacePage("encrypted_survey", [real, "low entropy tail candidates"], limit)
    note_names = NoReplacePage("encrypted_survey", [real, "note name candidates"], limit)
    skipped = NoReplacePage("encrypted_survey", [real, "entries skipped"], limit)
    exceptions = NoReplacePage("encrypted_survey", [real, "directories and entries not read"], limit)
    exclusions = []
    counters = {"directories_visited": 0, "directories_failed": 0, "directories_excluded": 0, "entries_failed": 0,
                "links_not_followed": 0, "special_files_skipped": 0, "regular_files_visited": 0,
                "candidate_files": 0, "noncandidate_files": 0, "unmeasured_files": 0, "read_failed_files": 0,
                "profile_failures": 0, "mtime_unconvertible": 0, "appended_extensions_withheld": 0}
    PROGRESS["coverage"] = counters
    sizes = {"candidate_bytes": 0, "noncandidate_bytes": 0, "unmeasured_bytes": 0, "read_failed_bytes": 0}
    unmeasured_by_reason = collections.Counter()
    appended = collections.Counter()
    appended_over = [0]
    appended_from = {}           # an appended extension -> the name of a file that is printed as it is and carries it
    all_hours, cand_hours = collections.Counter(), collections.Counter()
    all_over, cand_over = [0], [0]
    tails = collections.Counter()
    shared = None
    sampled = 0
    not_profiled = collections.Counter()
    stopped = {}

    for path, st in walk(root, set(exclude_top), counters, exceptions, skipped, exclusions, census, stopped):
        counters["regular_files_visited"] += 1
        size = st.st_size
        modified = iso_utc(st.st_mtime_ns)
        shown_path = display(path)
        row = {"record": "file", "file": shown_path, "bytes": size, "mtime_ns": st.st_mtime_ns, "modified_utc": modified}
        if modified is None:
            counters["mtime_unconvertible"] += 1
            row["mtime_error"] = "the modification time is outside what a datetime holds"
        else:
            bump(all_hours, hour_bucket(modified), HOUR_CAP, all_over)
        base = os.path.basename(path)
        evidence = evidence_of(base)
        if evidence is None and size < 100000:
            note_names.add({"file": shown_path, "bytes": size})
        reasons, ext = name_reasons(base)
        # An extension is a piece of the name: when the name is withheld the extension is withheld with it (it can be the identifier),
        # counted and not tabled, whatever the file's other fields say.
        if ext and evidence is None and shown(base, count=False) != base:
            counters["appended_extensions_withheld"] += 1
            ext_printed = EXT_WITHHELD
            ext = None
        else:
            ext_printed = ext
        row["appended_extension"] = ext_printed
        head = None
        head_exact = None
        fd = None
        failure = None
        unmeasured = None
        if size <= SMALL:
            unmeasured = "too_small_for_entropy"
        else:
            need = min(WINDOW, size)
            if not budget.allows(need):
                unmeasured = "read_budget_spent"
            else:
                try:
                    fd, fst = open_regular(path)
                    block = pread_full(fd, need, 0)
                    budget.spend(len(block))
                    head_exact = entropy_exact(block)
                    head = shown_entropy(head_exact)
                    size = fst.st_size  # what the open file is, if it changed since it was listed
                except OSError as exc:
                    failure = describe(exc)
                    if fd is not None:
                        os.close(fd)
                        fd = None
        row["head_entropy"] = head
        if failure:
            counters["read_failed_files"] += 1
            sizes["read_failed_bytes"] += st.st_size
            row.update({"status": "read_failed", "reason": "the file could not be read", "error": failure})
            if reasons:
                row["name_reasons"] = reasons
            census.add(row, evidence)
            continue
        found = list(reasons)
        if head_exact is not None and head_exact >= HEAD_THRESHOLD:
            found.append("head_entropy_at_least_7.5")
            parts = base.lower().rsplit(".", 1)
            if len(parts) == 2 and parts[1] in COMPRESSED_FORMATS and not reasons:
                row["alternative_explanation"] = "its extension (%s) names a format that is normally compressed: high entropy is what it looks like whole" % parts[1]
        if found:
            row["status"] = "candidate"
            row["reasons"] = found
            counters["candidate_files"] += 1
            sizes["candidate_bytes"] += st.st_size
            if ext:
                bump(appended, ext, EXT_CAP, appended_over)
                if evidence is not None:
                    appended_from.setdefault(ext, evidence)
            if modified is not None:
                bump(cand_hours, hour_bucket(modified), HOUR_CAP, cand_over)
            if head is None:
                row["entropy_unmeasured"] = unmeasured
            # Profile: the first `sample` candidates that have a head window, while the budget lasts.
            if head is not None and fd is not None:
                if sampled >= sample_size:
                    row["profiled"] = False
                    row["profile_skipped"] = "sample_limit"
                    not_profiled["sample_limit"] += 1
                else:
                    places = window_places(size)
                    lengths = {name: min(WINDOW, size - at) for name, at in places}
                    need = lengths["middle"] + lengths["end"] + min(tail_bytes, size)
                    if not budget.allows(need):
                        row["profiled"] = False
                        row["profile_skipped"] = "read_budget_spent"
                        not_profiled["read_budget_spent"] += 1
                    else:
                        try:
                            windows = [{"name": "head", "offset": 0, "length": lengths["head"], "entropy": head}]
                            end_exact = None
                            for name, at in places[1:]:
                                block = pread_full(fd, lengths[name], at)
                                budget.spend(len(block))
                                exact = entropy_exact(block)
                                if name == "end":
                                    end_exact = exact
                                windows.append({"name": name, "offset": at, "length": len(block), "entropy": shown_entropy(exact)})
                            tail = b""
                            if tail_bytes:
                                tail = pread_full(fd, min(tail_bytes, size), max(0, size - tail_bytes))
                                budget.spend(len(tail))
                            sampled += 1
                            row["profiled"] = True
                            row["windows"] = windows
                            row["windows_overlap"] = overlap(windows)
                            if tail:
                                row["tail_hex"] = tail.hex()
                                tails[tail.hex()] += 1
                                shared = tail if shared is None else common_suffix(shared, tail)
                            if end_exact is not None and end_exact < END_LOW:
                                low_tail.add({"file": shown_path, "bytes": size, "end_entropy": windows[2]["entropy"],
                                              "head_entropy": head, "windows": windows,
                                              "basis": "candidate: the end window reads below 6.5 bits per byte. That can be "
                                                       "padding, zero fill, a trailer or an unencrypted region; it does not show "
                                                       "what was encrypted, and encryption between the windows is not seen"}, evidence)
                        except OSError as exc:
                            counters["profile_failures"] += 1
                            row["profiled"] = False
                            row["profile_skipped"] = "read_failed"
                            row["profile_error"] = describe(exc)
            elif head is None:
                row["profiled"] = False
                row["profile_skipped"] = unmeasured
                not_profiled[unmeasured] += 1
            row = candidates.add(row, evidence)
            census.add(row, evidence)
        elif head is None:
            row["status"] = "unmeasured"
            row["reason"] = unmeasured
            row["reasons"] = []
            counters["unmeasured_files"] += 1
            sizes["unmeasured_bytes"] += st.st_size
            unmeasured_by_reason[unmeasured] += 1
            census.add(row, evidence)
        else:
            row["status"] = "noncandidate"
            row["reasons"] = []
            counters["noncandidate_files"] += 1
            sizes["noncandidate_bytes"] += st.st_size
            if full_census:
                census.add(row, evidence)
        if fd is not None:
            os.close(fd)

    def hours(counter, key):
        page = NoReplacePage("encrypted_survey", [real, key], limit)
        for hour, n in sorted(counter.items(), key=lambda kv: (-kv[1], kv[0])):
            page.add({"hour_utc": hour, "files": n})
        return page

    all_page = hours(all_hours, "all files by hour")
    cand_page = hours(cand_hours, "candidates by hour")
    ext_page = NoReplacePage("encrypted_survey", [real, "appended extensions"], limit)
    for ext, n in sorted(appended.items(), key=lambda kv: (-kv[1], kv[0])):
        ext_page.add({"extension": ext, "files": n}, appended_from.get(ext))
    tail_page = NoReplacePage("encrypted_survey", [real, "repeated tails"], limit)
    for tail, n in sorted(tails.items(), key=lambda kv: (-kv[1], kv[0])):
        if n > 1:
            tail_page.add({"tail_hex": tail, "files": n, "basis": "observation"})
    shared_out = None
    if sum(tails.values()) > 1 and shared is not None and len(shared) >= 4:
        shared_out = {"suffix_hex": shared.hex(), "bytes": len(shared), "across_files": sum(tails.values()), "basis": "observation",
                      "pending": "a match against a reference for a family, with the suffix and its position",
                      "caveat": "every sampled tail ends with these bytes. Padding, an ordinary format trailer, duplicated "
                                "content or one tool's output also do; this is not a finding about the family"}

    pages = {"candidates": candidates.finish(), "low_entropy_tail_candidates": low_tail.finish(),
             "note_name_candidates": note_names.finish(), "skipped": skipped.finish(), "exceptions": exceptions.finish(),
             "all_files_mtime_hourly": all_page.finish(), "candidate_mtime_hourly": cand_page.finish(),
             "appended_extension_observations": ext_page.finish(), "repeated_tails": tail_page.finish()}
    OWN_NAMES.update(page["all_results"] for page in pages.values() if page.get("all_results"))

    c = counters
    reasons = []
    if c["read_failed_files"]:
        reasons.append("%d files could not be read (read_failed)" % c["read_failed_files"])
    if c["profile_failures"]:
        reasons.append("%d candidates could not be profiled: a read failed" % c["profile_failures"])
    if c["directories_failed"] or c["entries_failed"]:
        reasons.append("%d directories could not be listed and %d entries could not be examined" % (c["directories_failed"], c["entries_failed"]))
    if c["directories_excluded"]:
        reasons.append("%d top-level directories were excluded (exclude_top_level_dirs) and not read" % c["directories_excluded"])
    if c["links_not_followed"] or c["special_files_skipped"]:
        reasons.append("%d links were not followed and %d special files were not opened" % (c["links_not_followed"], c["special_files_skipped"]))
    spent = unmeasured_by_reason.get("read_budget_spent", 0) + not_profiled.get("read_budget_spent", 0)
    if spent:
        reasons.append("the read budget (%d bytes) was spent: %d files have no entropy measurement or no profile" % (budget.total, spent))
    if not_profiled.get("sample_limit"):
        reasons.append("%d candidates were not profiled: the sample (%d) was reached, so their middle and end windows and tails were not read "
                       "(raise sample, at most %d, to profile more)" % (not_profiled["sample_limit"], sample_size, MAX_SAMPLE))
    if stopped:
        reasons.append("the time limit (max_seconds %d) was reached: %d entries of the directory being read and at least %d directories were "
                       "not examined, and nothing under them is counted" % (max_seconds, stopped["entries_not_examined"], stopped["directories_not_entered"]))
    where_every_one = ("the census has every one" if full_census and not census_problem
                       else "the census does not list files that matched nothing, so those are counted nowhere")
    for name, over in (("all files", all_over), ("candidates", cand_over)):
        if over[0]:
            reasons.append("the %s hour table is capped at %d distinct hours: %d files are not counted in it (%s)" % (name, HOUR_CAP, over[0], where_every_one))
    if appended_over[0]:
        reasons.append("the extension table is capped at %d distinct extensions: %d candidates are not counted in it (the census has every one)"
                       % (EXT_CAP, appended_over[0]))
    if census_problem:
        reasons.append(census_problem)
    if BOUNDARY["replaced"]:
        reasons.append("%d strings held an identifier-shaped text that the first rule missed and were replaced at the output (see boundary)"
                       % BOUNDARY["replaced"])
    complete = "partial" if reasons else "complete"
    basis = ("; ".join(reasons) if reasons else
             "every entry under the root was visited and accounted for (candidate, noncandidate, unmeasured or read_failed), the read "
             "budget and the time limit were not reached, every candidate of more than 4096 bytes was profiled and no table was capped")
    receipt = {"parser": PARSER, "complete": complete, "status": complete, "status_basis": basis, "partial_reasons": reasons,
               "coverage": {**counters, "bytes_read": budget.read, "paths_withheld": WITHHELD_PATHS[0]}, "bytes": sizes,
               "parameters": {"root": shown_root, "sample": sample_size, "tail_bytes": tail_bytes, "read_budget_bytes": budget.total,
                              "max_seconds": max_seconds, "exclude_top_level_dirs": [shown(x, count=False) for x in exclude_top],
                              "census": full_census}}
    if getattr(census, "shown", None):
        OWN_NAMES.add(census.shown)

    regular = counters["regular_files_visited"]
    # The answer is read back before the census is closed, so that a string only the answer holds (an unrecognised parameter named like an
    # identifier) that is replaced there is counted when the receipt is read back: the receipt and the answer say the same status.
    answer = release({
        "root": shown_root,
        "parser": PARSER,
        "complete": complete,
        "status": complete,
        "status_basis": basis,
        "partial_reasons": reasons,
        "measures": "A survey of candidates. A file is a candidate when its name has an extension after a known one or its first "
                    "64 KiB reads at 7.5 bits per byte or more; a compressed archive reads the same way. It does not measure how "
                    "much of any file was encrypted, whether a file is whole, which family wrote it or when anything ran. "
                    "noncandidate means only that neither heuristic matched.",
        "coverage": {**counters, "unmeasured_by_reason": dict(unmeasured_by_reason), "bytes_read": budget.read,
                     "read_budget_bytes": budget.total},
        "time_limit": {"max_seconds": max_seconds, "reached": bool(stopped), **stopped},
        "bytes": sizes,
        "candidate_file_fraction": round(counters["candidate_files"] / regular, 4) if regular else None,
        "fraction_basis": "candidate files over regular files visited (unmeasured and unreadable files are in the denominator)",
        "candidates": candidates.page,
        "low_entropy_tail_candidates": low_tail.page,
        "appended_extension_observations": ext_page.page,
        "extension_table": "capped: %d distinct extensions held, %d later files not counted here (the census has every one)" % (EXT_CAP, appended_over[0]) if appended_over[0] else "complete",
        "all_files_mtime_hourly": all_page.page,
        "candidate_mtime_hourly": cand_page.page,
        "clock": "filesystem mtime as collected (the extraction or copy that made this tree can change it), UTC, hourly buckets; "
                 "not an execution time of any program, and not the time any file was encrypted",
        "histogram_tables": {
            name: ("capped: %d distinct hours held, %d files not counted here (%s)" % (HOUR_CAP, over[0], where_every_one) if over[0] else "complete")
            for name, over in (("all_files", all_over), ("candidates", cand_over))},
        "repeated_tails": tail_page.page,
        "shared_tail_suffix": shared_out,
        "note_name_candidates": note_names.page,
        "exclusions": exclusions,
        "skipped": skipped.page,
        "exceptions": exceptions.page,
        "paths_withheld": WITHHELD_PATHS[0],
        **({"paths_note": "A path component that holds a token shaped like an identifier (the shape is in the manifest, with the rates at "
                          "which it misses and at which it withholds an ordinary name), and the name of a file that is named like a "
                          "note (the pattern ransom_note_scan uses) and holds one, is withheld from every row of this answer and of the "
                          "files it names, once per printed path counted here: some families put the victim's identifier in a "
                          "directory or in the note's name. The name of any other file, an encrypted file's included, is printed as it "
                          "is. List the directory for a name that was withheld."} if WITHHELD_PATHS[0] else {}),
        "sampling": {"method": "first %d profile-eligible candidates in print order (depth first; directories and names ordered by the text the "
                               "answer prints for them, names that are withheld in an order drawn afresh every run, so which of them fall "
                               "in the sample differs between runs); not stratified; a candidate of 4096 bytes or less has no profile" % sample_size,
                     "sample": sample_size, "profiled": sampled, "candidates_not_profiled": dict(not_profiled),
                     "tail_bytes": tail_bytes, "window_bytes": WINDOW},
        "census": None if census_problem else {"file": census.shown, "rows": census.rows,
                   "scope": "every regular file visited with its status, and every entry skipped, excluded or not read; "
                            "the last line is a receipt" if full_census else
                            "candidates, unmeasured and unreadable files and every entry skipped, excluded or not read; "
                            "files that matched nothing are counted, not listed (census: false)"},
        "pages": pages,
        "truncated": any(p["truncated"] for p in pages.values()),
        **({"unrecognised_parameters": unknown} if unknown else {}),
        "note": "Candidates are leads. Entropy of three windows does not say what part of a file was encrypted, and an "
                "intermittent layout can fall between them; the sampled tails are bytes of the files and say nothing about a "
                "family until a reference matches. Take the questions this cannot answer (extent, recoverability, family, "
                "timing) to file-format validation, a known-good counterpart or a documented layout. coverage and complete say "
                "what was and was not read; a file in read_failed or unmeasured was not shown to be anything.",
    })
    census.finish(receipt)
    if getattr(census, "shown", None):
        OWN_NAMES.add(census.shown)
        if isinstance(answer.get("census"), dict):
            answer["census"]["file"] = census.shown
    print(json.dumps(answer, indent=2))


if __name__ == "__main__":
    try:
        main()
    except SystemExit as exc:
        if exc.code not in (0, None):
            drop_temporary_files()
        raise
    except Exception as exc:  # never an empty or clean answer for a failure
        drop_temporary_files()
        detail = describe(exc) if isinstance(exc, OSError) else "%s at %s" % (type(exc).__name__, where_it_failed(exc))
        fail("unexpected failure: %s" % detail)
