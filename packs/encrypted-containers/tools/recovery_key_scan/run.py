#!/usr/bin/env python3
"""Locate the key material that is already in the evidence, without reading it out.

Almost every container opened in a real case was opened with a key that was
sitting somewhere else in the same case. This sweep finds where, and says what
kind of thing it found. It never says what the thing is.

What it looks for:

    a BitLocker recovery password   48 digits in eight groups of six, in ASCII
                                    text or UTF-16LE text (Windows' own "save a
                                    recovery key" file is UTF-16LE)
    private keys                    the PEM header, with its type
    key files and databases         by name: .bek, id_*, kdbx, key4.db, the
                                    keychains, Login Data, logins.json,
                                    .ppk/.pem/.p12/.pfx, and the names people
                                    save a recovery key under

The 48-digit format carries its own check: each of the eight groups is a
multiple of eleven whose quotient is below 65536 (so no group is above 720885),
which removes almost every coincidental match. `passes_structure_check` says all
eight groups pass. It means a plausible transcription of a recovery password. It
does not mean the value opens any volume. A value with a failing group is still
reported, marked, because a partial transcription is a lead.

THE SECRET-SAFE OUTPUT PATTERN (docs/packs.md, "Secrets and sensitive output").
This tool is its reference implementation; a tool that can reach secret material
copies `SecretValues` below and follows the same rules.

  1. The answer carries presence, kind, location (file and offset), length and a
     structure result. It carries no value, no characters of one, no masked
     "shape" and no hash, digest or fingerprint of one, however short or salted.
     A finding's `finding_id` is a sequence number and is derived from nothing.
  2. A value is written only when the caller asks (`write_values: true`), only
     when the tool runs as a job (JOB_ID and OUT are set) that the harness ran as
     secret output (SECRET_OUTPUT=1 in the process; the manifest's `secret_output`
     makes a job with write_values one), and only to a file under $OUT. The skill
     that sends the agent here says the job runs with `secret_output: true`, which
     seals every output of the job as sensitive. Outside a job, or in a job that is
     not secret output, the request is refused and nothing is written.
  3. The value file is JSON Lines, mode 0600, created exclusively; each row
     names the same `finding_id`, file and offset as the answer. The answer
     names the file and says `contains_secret_values: true`.
  4. A secret is never on a command line. This tool takes a path and flags only.
  5. A path is printed with any component shaped like the secret withheld (a file or a
     directory named after a recovery password would otherwise print it), and so is a
     component shaped like any identifier or secret (the SHARED NAMES block says which
     shapes, and which are not recognised), in the answer, in the files it names and in
     the digest that names a paging file. The values file keeps the real path.
  6. What is about to be printed or paged is read once more by a check of its own (the
     output check); a string it finds suspect is replaced and the answer is partial.

A value is found when it is not glued to more digits: "key_<value>" and "(<value>)" are
found, "<value>7" and "7<value>" are not (a group of seven digits is no group).

The tool has its own clock (`max_seconds`, default 480, below the manifest's 600) and
stops on SIGTERM, SIGINT and SIGHUP: either way it finishes the pages it has, closes the
values file, and prints one answer that says it is partial, names the files it did not
read and the directories it did not enter, and exits (128 + the signal for a signal).
"""
import errno
import json
import os
import re
import stat
import sys

# Lossless paging (the same in every library tool that pages): the page an
# agent reads stays small, and when there are more rows the whole result is
# written as JSON Lines under work/<agent>/tool-output (in a job, $OUT/tool-output)
# and named. The file name is a digest of the page's key (a path), never of a value.
import hashlib
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


class SealedPage(NoReplacePage):
    """A page whose every row passes the output check before it is kept or written."""

    def add(self, row: object) -> None:
        super().add(seal(row))


class SecretValuesRefused(Exception):
    pass


class SecretValues:
    """Where a value goes when, and only when, the caller asked for it.

    The reference implementation of the secret-safe output pattern: copy this
    class unchanged into a tool that has to produce a secret, and call `add`
    once per finding with the finding's id, its locator and the value. With
    `enabled` false it writes nothing and `summary()` says so.
    """

    NAME = "recovery-passwords.jsonl"

    def __init__(self, enabled: bool):
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
                "file, not a sealed secret output. Run this as job_run tool=recovery_key_scan with "
                "secret_output: true, and ask again there. Nothing was written."
            )
        if os.environ.get("SECRET_OUTPUT") != "1":
            raise SecretValuesRefused(
                "write_values is refused in a job that was not run as secret output: its files would "
                "be sealed as ordinary output. The harness sets SECRET_OUTPUT=1 for a secret job's "
                "process and it is not set here. Run this as job_run tool=recovery_key_scan (its "
                "manifest makes the job secret output), or give a command job secret_output: true; "
                "if that is refused the same way, this run's harness does not set the variable and the "
                "values mode is not available in it. Nothing was written."
            )
        self.path = Path(self.out) / self.NAME
        self.shown = "store/jobs/%s/out/%s" % (re.sub(r"[^A-Za-z0-9_.-]", "_", self.job), self.NAME)
        # Created now, before anything is scanned: a file or a link already at that name is
        # refused by name at once (O_EXCL does not follow a link, a dangling one included),
        # instead of failing, or writing through it, after the scan. With nothing found it
        # stays as an empty file, mode 0600, and the answer says written: 0.
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            fd = os.open(str(self.path), os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        except FileExistsError:
            raise SecretValuesRefused("the values file already exists: %s" % self.shown)
        except OSError as exc:
            raise SecretValuesRefused("the values file could not be created: %s (%s)" % (self.shown, describe(exc)))
        self._fh = os.fdopen(fd, "w", encoding="utf-8")

    def add(self, finding_id: str, locator: dict, value: str) -> None:
        if not self.enabled:
            return
        # One row, one write: a stop between two writes cannot leave half a row. ASCII only, so a file name that is not UTF-8
        # (a lone surrogate) is written escaped, not refused.
        self._fh.write(json.dumps({"finding_id": finding_id, **locator, "value": value}, ensure_ascii=True) + "\n")
        self.written += 1

    def close(self) -> None:
        if self._fh is not None:
            self._fh.flush()
            os.fsync(self._fh.fileno())
            self._fh.close()
            self._fh = None

    def summary(self) -> dict:
        return {
            "requested": self.enabled,
            "written": self.written,
            "values_file": self.shown if self.enabled else None,
            "contains_secret_values": self.written > 0,
            "format": "JSON Lines, mode 0600: finding_id, file (the real path), offset, encoding, value" if self.enabled else None,
        }


PARSER = "recovery_key_scan/3"
CHUNK = 4 << 20
# Longer than the longest thing matched (110 bytes of UTF-16LE text), so a match
# across a read boundary is whole in the next window.
OVERLAP = 256
# A match that ends this close to a window's end waits for the next window: the
# UTF-16LE pattern looks two bytes past its end.
MARGIN = 2
DEFAULT_BUDGET = 8 << 20
DEFAULT_SECONDS = 480           # the manifest allows 600; the tool stops at this and still prints what it has
MAX_SECONDS = 540
# Recovery passwords seen are compared with each other to say "the same value as
# F000001" without saying the value; the comparison is held in memory, and capped.
DUPLICATE_CAP = 50000

# A value is eight groups of six digits that is not glued to more digits. The scan finds the DASH that follows the first group (a
# pattern that starts with a literal is searched at the speed of a byte search) and checks the first group and what precedes it by
# hand: the matches are the ones a pattern with a look-behind would give, found without trying every byte.
ASCII_TAIL = re.compile(rb"-([0-9]{6})-([0-9]{6})-([0-9]{6})-([0-9]{6})-([0-9]{6})-([0-9]{6})-([0-9]{6})(?![0-9])")
UTF16_GROUP = rb"((?:[0-9]\x00){6})"
UTF16_TAIL = re.compile(rb"-\x00" + (rb"-\x00".join([UTF16_GROUP] * 7)) + rb"(?![0-9]\x00)")
UTF16_FIRST = re.compile(rb"(?:[0-9]\x00){6}\Z")
PEM = re.compile(rb"-----BEGIN ((?:[A-Z]{2,10} ){0,2}PRIVATE KEY)-----")
# The types a private key header is reported under; any other type is "other". The text is the evidence's, and is not echoed.
PEM_KNOWN = {"", "RSA", "EC", "DSA", "OPENSSH", "ENCRYPTED", "PGP"}
NAME_HINTS = [
    (re.compile(r"\.bek$", re.I), "BitLocker startup key"),
    (re.compile(r"bitlocker.*recovery|recovery.*key", re.I), "a name people save a recovery key under"),
    (re.compile(r"^id_(rsa|dsa|ecdsa|ed25519)$", re.I), "an SSH private key"),
    (re.compile(r"\.kdbx$", re.I), "a KeePass database"),
    (re.compile(r"^key[34]\.db$", re.I), "the Firefox key database"),
    (re.compile(r"^login\.keychain(-db)?$", re.I), "a macOS keychain"),
    (re.compile(r"^FileVaultMaster\.keychain$", re.I), "a FileVault institutional key"),
    (re.compile(r"^Login Data$", re.I), "Chromium saved passwords"),
    (re.compile(r"^logins\.json$", re.I), "Firefox saved passwords"),
    (re.compile(r"\.(ppk|pem|p12|pfx)$", re.I), "a key or certificate store"),
]
# Directories of a mounted Linux root that hold no evidence. Applied to the
# top of the tree walked only, and every one skipped is reported: a directory
# called dev deeper in the tree is evidence, and is read.
SKIP_TOP_DIRS = {"proc", "sys", "dev"}


def fail(message, **extra):
    claim_answer()
    remove_pending_pages()
    print(json.dumps(seal({"error": message, "status": "failed",
                           "status_basis": "the tool stopped with an error (see error); nothing was scanned or the scan was abandoned", **extra}),
                     ensure_ascii=True))
    raise SystemExit(1)


class Hit:
    """A recovery password found in a window: where it starts and ends, and its eight groups."""

    def __init__(self, start, end, groups):
        self._start, self._end, self._groups = start, end, groups

    def start(self):
        return self._start

    def end(self):
        return self._end

    def groups(self):
        return self._groups


def ascii_hits(window):
    """The recovery passwords in ASCII text in `window`, left to right, none overlapping the one before."""
    pos = last_end = 0
    while True:
        m = ASCII_TAIL.search(window, pos)
        if m is None:
            return
        s = m.start() - 6
        first = window[s:s + 6] if s >= last_end else b""
        if len(first) == 6 and first.isdigit() and not (s > 0 and window[s - 1:s].isdigit()):
            yield Hit(s, m.end(), (first,) + m.groups())
            pos = last_end = m.end()
        else:
            pos = m.start() + 1


def utf16_hits(window):
    """The same for UTF-16LE text."""
    pos = last_end = 0
    while True:
        m = UTF16_TAIL.search(window, pos)
        if m is None:
            return
        s = m.start() - 12
        first = window[s:s + 12] if s >= last_end else b""
        before = window[s - 2:s] if s >= 2 else b""
        if len(first) == 12 and UTF16_FIRST.match(first) and not (len(before) == 2 and before[0:1].isdigit() and before[1] == 0):
            yield Hit(s, m.end(), (first,) + m.groups())
            pos = last_end = m.end()
        else:
            pos = m.start() + 1


def valid_group(value):
    """Each group of a BitLocker recovery password is a multiple of 11 whose quotient is below 65536."""
    try:
        number = int(value)
    except ValueError:
        return False
    return number % 11 == 0 and number // 11 < 65536


def describe(exc):
    code = errno.errorcode.get(exc.errno, "") if getattr(exc, "errno", None) else ""
    return withhold("%s%s: %s" % (type(exc).__name__, " " + code if code else "", getattr(exc, "strerror", None) or str(exc)))


class FileStats:
    def __init__(self):
        self.bytes_read = 0
        self.error = None
        self.stopped = False


def scan_stream(fh, budget, stats):
    """Yield (kind, start, end, match) for what is in the first `budget` bytes of `fh`.

    The file is read CHUNK bytes at a time and held in a window of the chunk and
    the last OVERLAP bytes of the one before, so memory does not follow the file
    or the budget. A match is yielded once, at its true offset, when the window
    that first holds all of it is scanned. A read error stops the stream after
    the windows already read are scanned; the error is left in `stats.error`. A
    stop (a signal, or the time limit) is checked before each read: the windows
    already read are scanned, `stats.stopped` is set, and the rest of the file is
    not read.
    """
    carry, base, accepted_through = b"", 0, -1
    try:
        data = fh.read(min(CHUNK, budget))
    except OSError as exc:
        stats.error = exc
        return
    stats.bytes_read += len(data)
    while True:
        nxt = b""
        if data and stats.bytes_read < budget:
            if stop_wanted():
                stats.stopped = True
            else:
                try:
                    nxt = fh.read(min(CHUNK, budget - stats.bytes_read))
                except OSError as exc:
                    stats.error = exc
                stats.bytes_read += len(nxt)
        final = not nxt
        window = carry + data
        found = []
        for finder, kind in ((ascii_hits(window), "ascii"), (utf16_hits(window), "UTF-16LE"), (PEM.finditer(window), "pem")):
            for m in finder:
                end = base + m.end()
                if end <= accepted_through:
                    continue
                if not final and m.end() > len(window) - MARGIN:
                    continue
                found.append((base + m.start(), kind, m))
        for start, kind, m in sorted(found, key=lambda f: f[0]):
            yield kind, start, m
        if final:
            return
        accepted_through = base + len(window) - MARGIN
        keep = window[-OVERLAP:]
        base += len(window) - len(keep)
        carry, data = keep, nxt


class Walk:
    """The regular files under `top`, in name order, following no link; what it has not reached is known at any moment.

    A directory that cannot be listed, a link and a file that is not a regular
    file are reported as exceptions and counted; none is ever dropped quietly.
    `entries` and `next` are the directory being read and the index of its next
    entry, `stack` the directories not yet entered: what a stop leaves unread.
    """

    def __init__(self, top, exceptions, counters):
        self.stack = [(top, True)]
        self.entries, self.next, self.found_dirs = [], 0, []
        self._files = self._generate(exceptions, counters)

    def __iter__(self):
        return self._files

    def _generate(self, exceptions, counters):
        while self.stack:
            directory, is_top = self.stack.pop()
            try:
                with os.scandir(directory) as it:
                    self.entries, self.next = sorted(it, key=lambda e: e.name), 0
            except OSError as exc:
                self.entries, self.next = [], 0
                counters["directories_failed"] += 1
                exceptions.add({"path": shown(directory), "status": "failed", "what": "directory", "reason": "the directory could not be listed", "error": describe(exc)})
                continue
            subdirs = self.found_dirs = []
            while self.next < len(self.entries):
                entry = self.entries[self.next]
                self.next += 1
                try:
                    if entry.is_symlink():
                        counters["entries_skipped"] += 1
                        exceptions.add({"path": shown(entry.path), "status": "skipped", "reason": "a symbolic link: links are not followed, and the target is read where it lies if it is in the tree"})
                        continue
                    if entry.is_dir(follow_symlinks=False):
                        if is_top and entry.name in SKIP_TOP_DIRS:
                            counters["entries_skipped"] += 1
                            exceptions.add({"path": shown(entry.path), "status": "skipped", "reason": "a top-level %s directory of a Linux root: its contents were not scanned; name it as the path to scan it" % entry.name})
                            continue
                        subdirs.append(entry.path)
                        continue
                    mode = entry.stat(follow_symlinks=False).st_mode
                except OSError as exc:
                    counters["files_attempted"] += 1
                    counters["files_failed"] += 1
                    exceptions.add({"path": shown(entry.path), "status": "failed", "reason": "the entry could not be examined", "error": describe(exc)})
                    continue
                if not stat.S_ISREG(mode):
                    counters["entries_skipped"] += 1
                    exceptions.add({"path": shown(entry.path), "status": "skipped", "reason": "not a regular file (%s)" % kind_of(mode)})
                    continue
                yield entry.path, entry.stat(follow_symlinks=False).st_size
            self.entries, self.next, self.found_dirs = [], 0, []
            self.stack.extend((d, False) for d in reversed(subdirs))

    def unreached(self):
        """(the entries of the directory being read that were not looked at, the directories found but not yet entered), as paths."""
        return [e.path for e in self.entries[self.next:]], list(self.found_dirs) + [d for d, _top in reversed(self.stack)]


def kind_of(mode):
    for test, name in ((stat.S_ISFIFO, "a named pipe"), (stat.S_ISSOCK, "a socket"), (stat.S_ISBLK, "a block device"),
                       (stat.S_ISCHR, "a character device"), (stat.S_ISDIR, "a directory")):
        if test(mode):
            return name
    return "a special file"


def optional_bool(args, key):
    value = args.get(key, False)
    if not isinstance(value, bool):
        fail("%s must be true or false" % key)
    return value


STATE = {"values": None}


def last_word(signum):
    values = STATE["values"]
    if values is not None:
        values.close()
    interrupted_answer(signum, written_values=values.written if values is not None else 0)


def private_key_type(m):
    head = m.group(1).decode("ascii", "replace")
    return head if head[:-len("PRIVATE KEY")].strip() in PEM_KNOWN else "other"


def main():
    install_stop(last_word, cooperative=True)
    try:
        args = json.load(sys.stdin)
    except ValueError as exc:
        fail("arguments are not valid JSON", reason=withhold(str(exc)))
    if not isinstance(args, dict):
        fail("arguments must be a JSON object")
    path = args.get("path")
    if not isinstance(path, str) or not path:
        fail("path is required: a directory to walk or a blob to sweep")
    if not os.path.exists(path):
        fail("no such file or directory", path=shown(path))
    budget = args.get("max_bytes_per_file", DEFAULT_BUDGET)
    if not isinstance(budget, int) or isinstance(budget, bool) or budget < 1024:
        fail("max_bytes_per_file must be an integer of at least 1024")
    limit = args.get("limit", 200)
    if not isinstance(limit, int) or isinstance(limit, bool) or limit < 1:
        fail("limit must be a positive integer")
    seconds = args.get("max_seconds", DEFAULT_SECONDS)
    if not isinstance(seconds, int) or isinstance(seconds, bool) or not 1 <= seconds <= MAX_SECONDS:
        fail("max_seconds must be an integer from 1 to %d (the tool's own time limit; the manifest allows 600)" % MAX_SECONDS)
    set_deadline(seconds)
    write_values = optional_bool(args, "write_values")
    try:
        values = SecretValues(write_values)
    except SecretValuesRefused as exc:
        fail(str(exc), write_values="refused", written=False)
    STATE["values"] = values
    STOP["cleanup"].append(values.close)

    real = shown(os.path.realpath(path), count=False)
    findings = SealedPage("recovery_key_scan", [real, "findings"], limit)
    named = SealedPage("recovery_key_scan", [real, "files worth opening"], limit)
    exceptions = SealedPage("recovery_key_scan", [real, "files not read, or not read whole"], limit)
    counters = {"files_attempted": 0, "files_read": 0, "files_partial": 0, "files_failed": 0, "files_stopped": 0,
                "entries_skipped": 0, "directories_failed": 0, "entries_not_started": 0, "directories_not_entered": 0}
    totals = {"bytes_read": 0, "bytes_unread_in_partial_files": 0}
    passwords = {"found": 0, "pass_structure_check": 0}
    seen = {}
    capped = False
    serial = 0
    walker = None

    if os.path.isdir(path):
        walker = Walk(path, exceptions, counters)
        targets = iter(walker)
    elif os.path.isfile(path):
        targets = iter([(path, os.stat(path).st_size)])
    else:
        fail("path is neither a directory nor a regular file", path=shown(path))

    stopped_why = None
    try:
        for target, size in targets:
            if stop_wanted():
                stopped_why = stop_cause()
                counters["entries_not_started"] += 1
                exceptions.add({"path": shown(target), "status": "not started", "reason": "%s before this file was read" % stopped_why, "bytes": size})
                break
            base = os.path.basename(target)
            for pattern, meaning in NAME_HINTS:
                if pattern.search(base):
                    named.add({"file": shown(target), "bytes": size, "why": meaning})
                    break
            counters["files_attempted"] += 1
            stats = FileStats()
            try:
                fh = open(target, "rb")
            except OSError as exc:
                stats.error = exc
            else:
                # A read error ends the stream and is left in stats.error; what
                # was found before it is kept. An error writing a result is not
                # a read error and is not caught here.
                with fh:
                    for kind, start, m in scan_stream(fh, budget, stats):
                        if stop_wanted():
                            # A window of nothing but findings takes seconds to work through: the clock is read for each one. The
                            # findings of the window not yet worked through were not read: the file counts as read up to the first.
                            stats.stopped = True
                            stats.bytes_read = min(stats.bytes_read, start)
                            break
                        serial += 1
                        finding_id = "F%06d" % serial
                        if kind == "pem":
                            findings.add({"finding_id": finding_id, "file": shown(target), "offset": start,
                                          "kind": "private key", "key_type": private_key_type(m), "parser": PARSER})
                            continue
                        if kind == "ascii":
                            groups = [g.decode() for g in m.groups()]
                        else:
                            groups = [g.replace(b"\x00", b"").decode("ascii") for g in m.groups()]
                        canonical = "-".join(groups)
                        good = sum(1 for g in groups if valid_group(g))
                        row = {"finding_id": finding_id, "file": shown(target), "offset": start,
                               "kind": "BitLocker recovery password",
                               "encoding": "ASCII" if kind == "ascii" else "UTF-16LE",
                               "length": len(canonical), "groups_passing_check": good,
                               "passes_structure_check": good == 8, "parser": PARSER}
                        earlier = seen.get(canonical)
                        if earlier:
                            row["duplicate_of"] = earlier
                        elif len(seen) < DUPLICATE_CAP:
                            seen[canonical] = finding_id
                        else:
                            capped = True
                        passwords["found"] += 1
                        passwords["pass_structure_check"] += 1 if good == 8 else 0
                        findings.add(row)
                        values.add(finding_id, {"file": target, "offset": start, "encoding": row["encoding"],
                                                "passes_structure_check": good == 8}, canonical)
            totals["bytes_read"] += stats.bytes_read
            if stats.error is not None:
                counters["files_failed"] += 1
                exceptions.add({"path": shown(target), "status": "failed", "reason": "the file could not be read whole up to its budget",
                                "error": describe(stats.error), "bytes": size, "bytes_read": stats.bytes_read})
                continue
            if stats.stopped:
                stopped_why = stop_cause()
                counters["files_stopped"] += 1
                counters["files_partial"] += 1
                totals["bytes_unread_in_partial_files"] += min(size, budget) - stats.bytes_read
                exceptions.add({"path": shown(target), "status": "partial", "reason": "%s: the rest of this file was not read" % stopped_why,
                                "bytes": size, "bytes_read": stats.bytes_read, "bytes_unread": size - stats.bytes_read})
                break
            counters["files_read"] += 1
            if size > budget:
                counters["files_partial"] += 1
                totals["bytes_unread_in_partial_files"] += size - stats.bytes_read
                exceptions.add({"path": shown(target), "status": "partial", "reason": "read up to max_bytes_per_file; the rest was not read",
                                "bytes": size, "bytes_read": stats.bytes_read, "bytes_unread": size - stats.bytes_read})
        if stopped_why and walker is not None:
            # What the walk had not reached, named: the rest of the directory being read, and the directories not yet entered
            # (everything under those is unread, and how many files that is is not known).
            rest, unentered = walker.unreached()
            for item in rest:
                counters["entries_not_started"] += 1
                exceptions.add({"path": shown(item), "status": "not started", "reason": "%s before this entry was looked at" % stopped_why})
            for item in unentered:
                counters["directories_not_entered"] += 1
                exceptions.add({"path": shown(item), "status": "not started", "what": "directory", "reason": "%s before this directory was entered: nothing under it was read" % stopped_why})
    finally:
        values.close()

    pages = {"findings": findings.finish(), "files_worth_opening": named.finish(), "exceptions": exceptions.finish()}
    problems = [name for name, count in (("files failed", counters["files_failed"]), ("directories failed", counters["directories_failed"]),
                                         ("entries skipped", counters["entries_skipped"]), ("files read only in part", counters["files_partial"]),
                                         ("entries not started", counters["entries_not_started"]), ("directories not entered", counters["directories_not_entered"]))
                if count]
    answer = {
        "path": shown(path),
        "parser": PARSER,
        "findings": findings.page,
        "finding_count": pages["findings"]["matched"],
        "recovery_passwords": passwords,
        "duplicate_check": "capped: %d distinct values compared, later ones not" % DUPLICATE_CAP if capped else "complete",
        "files_worth_opening": named.page,
        "coverage": {**counters, "max_bytes_per_file": budget, "max_seconds": seconds, **totals},
        "exceptions": exceptions.page,
        "pages": pages,
        "secret_values": values.summary(),
        "paths_withheld": NAMES["strings"],
        **({"paths_note": "A path component shaped like a recovery password, an identifier or a secret is withheld from every path in this "
                          "answer and in the files it names (the real path of a recovery-password finding is in the values file when "
                          "write_values was asked for; otherwise list the directory). Withholding is by shape: an identifier of seven "
                          "characters or fewer, or of another shape, is printed."}
           if NAMES["strings"] else {}),
        "truncated": any(p["truncated"] for p in pages.values()),
        "note": "Locator output: no recovery value, fragment, masked shape or digest is in this answer or in any file "
                "it names, except the values file when write_values was asked for in a secret_output job. "
                "passes_structure_check means eight groups each divisible by 11 with a quotient below 65536: a "
                "plausible transcription, not proof that it opens any volume. files_read counts files read up to "
                "max_bytes_per_file; exceptions lists every file that failed, was skipped (links, special files, a "
                "top-level proc, sys or dev), was read only in part or was not started, with the bytes not read. A search that found "
                "nothing says nothing about a file listed there. Record in the report WHERE a key came from, because "
                "the report has to say how you got in; hand the value to the operator through the channel they named.",
    }
    if stopped_why:
        answer["interrupted"] = True
        answer["stopped_by"] = stopped_why
    status_basis = ("every file was read to the end of its budget and no entry was skipped, failed or left unread" if not problems else
                    "%s: see exceptions (the whole list is in pages.exceptions)" % ", ".join(problems))
    if stopped_why:
        status_basis = "%s; %s" % (stopped_why, status_basis)
    answer["status"] = "complete" if not problems and not stopped_why else "partial"
    answer["status_basis"] = status_basis
    sealed = seal(answer)
    if NAMES["replaced"]:
        sealed["output_check"] = {"replaced": NAMES["replaced"], "note": "a string the first layer let through was replaced by the output check"}
        sealed["status"] = "partial"
        sealed["status_basis"] += "; %d string(s) were replaced by the output check" % NAMES["replaced"]
    emit(sealed)


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except Exception as exc:  # never an empty or clean answer for a failure
        fail("unexpected failure: " + describe(exc) if isinstance(exc, OSError) else "unexpected failure: %s: %s" % (type(exc).__name__, withhold(str(exc))))
