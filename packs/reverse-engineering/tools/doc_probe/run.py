#!/usr/bin/env python3
"""Say what is inside a document, as bytes and never as an application would open it.

A document is a box. This tool reads the parts of the box that identify it and says, for each
structure, whether it read it whole. Four containers:

    OOXML / ZIP   (.docx, .xlsx, .pptx and their macro-enabled forms) the central directory is
                  read for member names, sizes, DOS times and flags; every part named *.rels is
                  parsed as XML for its relationships, and an External target is reported; with
                  `extract_to`, the members whose NAMES match a code-related pattern
                  (vbaProject.bin, vbaData.xml, a name containing "macros", a drs/ directory,
                  "activex") are written out byte for byte. A name pattern is not a content
                  check, and no other member is read.
    OLE           a compound file: byte markers by encoding. The directory and the streams are
                  not read.
    RTF           the literal control words \\objdata and \\objclass, with offsets.
    PDF           literal name tokens (/OpenAction, /AA, /JS, /JavaScript, /Launch, /Encrypt, ...)
                  with counts and offsets. A marker is not a resolved action, a page count or an
                  encryption verdict.

Decompression is bounded: a member is read only under a per-member budget, a total budget and an
expansion-ratio limit, and one that exceeds them is counted, not cut. Only stored and deflated members are
read (OOXML uses no other method): the standard library decompresses a bzip2 or LZMA chunk whole, with no
limit on its output, so such a member is counted as unsupported and never opened. The ZIP reader is given
the archive up to the end record this tool chose; a file with more than one end record is a problem, because
readers that choose differently list different directories. The tool has its own clock (max_seconds). Relationship parts are parsed
by an XML parser that refuses a DOCTYPE, so nothing is expanded. A member that cannot be read
(encrypted, corrupt, an unsupported method) is counted, never skipped. What a URL or a name can hold
(a credential, a token) is withheld from the answer, in the caller's path and in part names too, component
by component; the whole target goes to a sealed file only when `write_values` is asked for in a job, and the
real name behind a withheld name is kept in a private file.

Nothing here executes a document, a macro or a script, and nothing is fetched.
"""
import errno
import hashlib
import io
import json
import mmap
import os
import re
import struct
import sys
import time
import xml.parsers.expat
import zipfile
from pathlib import Path

TOOL = {"name": "doc_probe", "version": 3}
PARSER = "doc_probe/3"
NOTE = ("Static container triage only. Markers, procedure names and external relationships do not prove execution or "
        "retrieval. Record parser coverage before drawing an absence conclusion.")

CODE_PARTS = ("vbaproject.bin", "vbadata.xml", "macros", "drs/", "activex")
PDF_MARKERS = [
    (b"/OpenAction", "the catalog's open-action key: it names an action or a destination, not resolved here"),
    (b"/AA", "the additional-actions key: event-triggered actions on a page, annotation, field or the document; triggers not resolved here"),
    (b"/JavaScript", "the name token of a JavaScript action; its code is not located or read here"),
    (b"/JS", "the key that holds JavaScript in an action; its code is not located or read here"),
    (b"/Launch", "the name token of a launch action; whether it is reachable, and what it requests, is not determined here"),
    (b"/EmbeddedFile", "the type name of an embedded file stream"),
    (b"/RichMedia", "the name token of rich-media content or annotations"),
    (b"/SubmitForm", "the name token of a submit-form action"),
    (b"/ObjStm", "the type name of an object stream, whose objects are compressed and not searched here"),
    (b"/Encrypt", "the trailer key that names an encryption dictionary; the dictionary is not read here"),
]
# A PDF name ends at white space or a delimiter: /JS is not /JSON and /AA is not /AAA.
PDF_END = rb"(?![^\s()<>\[\]{}/%])"
PDF_RX = [(kw, re.compile(re.escape(kw) + PDF_END), what) for kw, what in PDF_MARKERS]
RTF_OBJDATA = re.compile(rb"\\objdata(?![A-Za-z])")
RTF_OBJCLASS = re.compile(rb"\\objclass(?![A-Za-z])\s*([A-Za-z0-9._]+)")
REL_NS = "http://schemas.openxmlformats.org/package/2006/relationships"

DEFAULT_MEMBER = 64 << 20          # bytes one member may expand to
DEFAULT_TOTAL = 256 << 20          # bytes all members may expand to, together
DEFAULT_MEMBERS = 10000            # members listed and read
DEFAULT_RATIO = 1000               # expanded bytes per compressed byte (deflate's own ceiling is about 1032)
DEFAULT_LIMIT = 1000               # rows of one table in the answer; the whole of a longer one is in a file
MAX_DIRECTORY_ENTRIES = 100000     # a central directory is loaded whole by the ZIP reader: more than this is not opened
MAX_DIRECTORY_BYTES = 64 << 20
RATIO_FLOOR = 1 << 20              # a member that expands to less than this is never judged by its ratio
MAX_RELATIONSHIPS = 1_000_000
PAGE = 1 << 16
MARKER_OFFSETS = 20
MAX_PROBLEMS = 100
DEFAULT_SECONDS = 100              # the tool's own clock: below the manifest's 120 s, so a slow file is a partial answer, not a kill
MAX_SECONDS = 110
OFFSETS_CAP = 100_000              # marker offsets written to the file; the count goes on past it
MAX_CLASSES = 500
METHODS_READ = (0, 8)              # stored and deflate: the only methods whose decompressor is asked for a bounded output
MIN_ENTRY = 46                     # the shortest central directory entry, so a directory of N bytes holds at most N / 46
# A name in a PDF that hides what follows it from a byte search: the stream behind it is not decoded here.
PDF_FILTER = re.compile(rb"/(?:FlateDecode|LZWDecode|ASCII85Decode|ASCIIHexDecode|RunLengthDecode|Crypt)(?![^\s()<>\[\]{}/%])")
HEAD_BYTES = 1024

ZIP_READ = ["the ZIP central directory: member names, sizes, DOS times, flags",
            "every part named *.rels, parsed as XML: relationships, and the External targets among them",
            "with extract_to: the members whose names match a code-related pattern, byte for byte"]
ZIP_NOT_READ = ["the contents of any other part (document.xml, shared strings, embedded objects under embeddings/)",
                "embedded OLE objects and packages, and the OLE compound file a vbaProject.bin is: it is extracted, not parsed",
                "macro source, compiled VBA (p-code) and Excel 4.0 macro sheets",
                "document protection and encryption: member flags only; an EncryptedPackage in an OLE wrapper is not detected",
                "digital-signature parts"]
PDF_READ = ["the %PDF- header line", "literal name tokens, with counts and the offsets of the first occurrences"]
PDF_NOT_READ = ["the object structure, cross-reference tables, revisions and filters; keywords inside compressed object streams are not seen",
                "names written with #-escapes", "the encryption dictionary and the security handler",
                "actions, their triggers and their targets: nothing is resolved", "the contents of JavaScript and embedded files"]
RTF_READ = ["the literal control words \\objdata and \\objclass, with offsets"]
RTF_NOT_READ = ["group structure and nesting", "the hex-encoded object data: it is not decoded", "OLE objects inside the RTF"]
OLE_READ = ["byte markers (ASCII and UTF-16LE) searched over the whole file"]
OLE_NOT_READ = ["the OLE directory and streams: a marker is a byte search, not a directory entry",
                "the VBA project, its modules and its p-code", "EncryptionInfo and EncryptedPackage streams (document protection)",
                "embedded objects"]

# BEGIN SHARED WITHHOLDING
# The same text is in pcap_extract, zeek_run, suricata_run and network_log_summary, so that the four tools withhold
# the same strings; tests/pack-network-withholding.test.ts holds the copies equal. An identifier-shaped string is
# withheld wherever the tool would print one: a name, a path component, a URL, a message that quotes either.
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


def token_spans(text):
    spans = [m.span() for m in _PREFIXED.finditer(text)]
    for m in _RUN.finditer(text):
        if _token_run(m.group()):
            spans.append(m.span())
    # A base64 token holds `/`: pieces too short to be one alone (an AWS-style secret has two) are caught as a whole.
    for m in _SLASHED.finditer(text):
        run = m.group()
        if "/" in run and sum(1 for p in run.split("/") if _randomish(p)) >= 3 and re.search(r"[0-9+]", run):
            spans.append(m.span())
    # A flagged piece takes the random-looking pieces next to it across a `/`: the head of a token is not printed.
    grown = []
    for start, end in spans:
        while start > 1 and text[start - 1] == "/":
            m = re.search(r"[A-Za-z0-9_+%-]+$", text[:start - 1])
            if not m or not _randomish(m.group()):
                break
            start = m.start()
        while end < len(text) - 1 and text[end] == "/":
            m = re.match(r"[A-Za-z0-9_+%-]+={0,2}", text[end + 1:])
            if not m or not _randomish(m.group()):
                break
            end = end + 1 + m.end()
        grown.append((start, end))
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


def describe(exc):
    code = errno.errorcode.get(exc.errno, "") if getattr(exc, "errno", None) else ""
    return scrub("%s%s: %s" % (type(exc).__name__, " " + code if code else "", getattr(exc, "strerror", None) or str(exc)), "text")


def in_job():
    return bool(os.environ.get("JOB_ID") and os.environ.get("OUT"))


VALUES = [None]    # the values file of this call, once it exists: an answer that fails after it was created names it


def shown_path(text):
    """A path as it may be printed: each component with anything token-shaped, or with user-info, withheld. A path is
    tested component by component, as an OPC part name or a file name is a path and not one token."""
    if not isinstance(text, str):
        return text
    return "/".join(scrub(part, "names") for part in text.split("/"))


def shown_deep(value, key=""):
    if key in ("head_hex", "tool"):
        return value
    if isinstance(value, str):
        return shown_path(value)
    if isinstance(value, list):
        return [shown_deep(v) for v in value]
    if isinstance(value, dict):
        return {k: shown_deep(v, k) for k, v in value.items()}
    return value


def fail(message, **extra):
    status = extra.pop("status", "failed")
    answer = {"error": scrub(message), "status": status, "tool": TOOL, **shown_deep(extra)}
    if VALUES[0] is not None:
        answer["secret_values"] = VALUES[0].summary()
    print(json.dumps(answer))
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

class LosslessPage:
    """The first `limit` rows of a table in the answer; when there are more, the whole table as JSON Lines in a
    file that is created exclusively (under a new name when the name is taken) and named in the answer. A table
    that cannot be written whole says so."""

    def __init__(self, tool, key, limit):
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
            self.dir.mkdir(parents=True, exist_ok=True)
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
            for n in range(1, 100):
                name = "%s.jsonl" % self.stem if n == 1 else "%s-%d.jsonl" % (self.stem, n)
                try:
                    fd = os.open(str(self.dir / name), flags, 0o600)
                except FileExistsError:
                    continue
                self.shown = self.prefix + name
                self._out = os.fdopen(fd, "w", encoding="utf-8")
                for kept in self.page:
                    self._write(kept)
                return
            self.not_written = "ninety-nine files of this name already exist in %s" % self.dir
        except OSError as exc:
            self.not_written = "the file could not be created in %s (%s)" % (self.dir, describe(exc))

    def _write(self, row):
        self._out.write(json.dumps(row, default=str))
        self._out.write("\n")

    def add(self, row):
        self.total += 1
        if len(self.page) < self.limit:
            self.page.append(row)
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
            result["not_written"] = self.not_written
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

    NAME = "doc-probe-values.jsonl"

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
                "file, not a sealed secret output. Run this as job_run tool=doc_probe with "
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
            raise SecretValuesRefused("the values file already exists: %s" % self.path)
        except OSError as exc:
            raise SecretValuesRefused("the values file could not be created: %s (%s)" % (self.path, describe(exc)))
        self._fh = os.fdopen(fd, "w", encoding="utf-8")

    def add(self, finding_id, locator, value):
        if not self.enabled or self._fh is None:
            return
        self._fh.write(json.dumps({"finding_id": finding_id, **locator, "value": value}))
        self._fh.write("\n")
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
            "format": ("JSON Lines, mode 0600: finding_id, part (the real name), relationship_id, type, value (the whole, "
                       "unredacted target)") if self.enabled else None,
        }


class Names:
    """The real name behind every name withheld from the answer: a private file (mode 0600, created exclusively, in the
    tool-output directory) written at the moment a name is withheld, whether or not write_values was given, so that no name
    is lost; with write_values the values file holds them as well. The answer names the file."""

    NAME = "doc-probe-withheld-names"

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
                self.dir.mkdir(parents=True, exist_ok=True)
                for n in range(1, 100):
                    name = "%s.jsonl" % self.NAME if n == 1 else "%s-%d.jsonl" % (self.NAME, n)
                    try:
                        fd = os.open(str(self.dir / name), os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
                    except FileExistsError:
                        continue
                    self._fh = os.fdopen(fd, "w", encoding="utf-8")
                    self.shown = self.prefix + name
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


def member_name(name, ctx):
    """A part name as it may be printed: tested one component at a time. The real name behind a withheld one is kept."""
    shown = shown_path(name)
    if shown != name:
        ctx.names.add(name, shown)
    return shown


# --- the call's bookkeeping ----------------------------------------------------------------------------------------------

class Ctx:
    def __init__(self, key, limit, values, seconds):
        self.key = key
        self.limit = limit
        self.values = values
        self.deadline = time.monotonic() + seconds
        self.seconds = seconds
        self.problems = []
        self.problems_dropped = 0
        self.limits = []
        self.pages = {}
        self.names = Names(values)

    def expired(self, where):
        if time.monotonic() <= self.deadline:
            return False
        self.limit_hit("time: %s stopped at max_seconds (%d); what was read is reported, and the counts are lower bounds" % (where, self.seconds))
        return True

    def problem(self, text):
        text = scrub(text)
        if text in self.problems:
            return
        if len(self.problems) >= MAX_PROBLEMS:
            self.problems_dropped += 1
            return
        self.problems.append(text)

    def limit_hit(self, text):
        text = scrub(text)
        if text not in self.limits:
            self.limits.append(text)

    def page(self, name, limit=None):
        if name not in self.pages:
            self.pages[name] = LosslessPage("doc_probe-" + name, [self.key, name], limit or self.limit)
        return self.pages[name]


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

    def __init__(self, fh, limit, zero_at):
        self._fh, self._limit, self._zero_at, self._pos = fh, limit, zero_at, 0

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
        buffer[:len(data)] = data
        self._pos += len(data)
        return len(data)


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
        raise Unreadable("over_budget", "the member declares %d bytes, over max_member_bytes (%d)" % (declared, budget.member))
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
                raise Unreadable("failed", "the member could not be read to its end (%s: %s)" % (type(exc).__name__, scrub(str(exc))))
            if not chunk:
                return
            read += len(chunk)
            budget.used += len(chunk)
            if read > budget.member:
                raise Unreadable("over_budget", "the member expanded past max_member_bytes (%d)" % budget.member)
            if read > RATIO_FLOOR and read > budget.ratio * max(info.compress_size, 1):
                raise Unreadable("over_budget", "the member expanded past max_ratio (%d) of its compressed size" % budget.ratio)
            if budget.used > budget.total:
                raise Unreadable("over_budget", "the members together expanded past max_total_bytes (%d)" % budget.total)
            yield chunk


class DoctypeRefused(Exception):
    pass


def parse_relationships(chunks, on_relationship):
    """Hand each Relationship element of an OPC relationships part to `on_relationship` as a dict of its attributes, read
    with an XML parser that knows namespaces, refuses a DOCTYPE and never expands an entity. Nothing is collected: a part of
    a million relationships costs no more memory than one. Returns counts of what was seen and what was not read."""
    parser = xml.parsers.expat.ParserCreate(namespace_separator=" ")
    parser.SetParamEntityParsing(xml.parsers.expat.XML_PARAM_ENTITY_PARSING_NEVER)
    notes = {"seen": 0, "other_namespace": 0, "over_cap": False}

    def start(name, attrs):
        if name == REL_NS + " Relationship":
            if notes["seen"] >= MAX_RELATIONSHIPS:
                notes["over_cap"] = True
                return
            notes["seen"] += 1
            on_relationship(attrs)
        elif name.rsplit(" ", 1)[-1] == "Relationship":
            notes["other_namespace"] += 1

    def doctype(*_args):
        raise DoctypeRefused()

    parser.StartElementHandler = start
    parser.StartDoctypeDeclHandler = doctype
    for chunk in chunks:
        parser.Parse(chunk, False)
    parser.Parse(b"", True)
    return notes


# --- ZIP ------------------------------------------------------------------------------------------------------------------------

def sanitize(name):
    return re.sub(r"[^A-Za-z0-9._-]", "_", name)[:120]


def extraction_target(extract_to, index, name, withheld):
    """A new, exclusively created file for a part: its own name, unless the name is withheld from the answer. A withheld name
    gives nothing of itself, not even its tail: an extension is kept only if it is short, plain and not token-shaped."""
    if withheld:
        ext = os.path.splitext(name)[1]
        if not (re.fullmatch(r"\.[A-Za-z0-9]{1,8}", ext) and not token_shaped(ext[1:]) and scrub(ext[1:], "names") == ext[1:]):
            ext = ""
        base = "%06d-withheld%s" % (index, ext)
    else:
        base = "%06d-%s" % (index, sanitize(name))
    for n in range(1, 100):
        candidate = base if n == 1 else "%s-%d" % (base, n)
        target = resolve_output(os.path.join(extract_to, candidate), "extract_to")
        try:
            fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        except FileExistsError:
            continue
        return target, fd
    raise OSError(errno.EEXIST, "ninety-nine files of this name already exist")


def probe_zip(path, size, ctx, args):
    out = {"container": "OOXML or ZIP", "timestamps_note": "ZIP member times are DOS local times with no zone recorded and a resolution of two seconds: they are claims, not UTC."}
    members = {"declared": 0, "listed": 0, "read": 0, "encrypted": 0, "flagged_encrypted": 0, "unsupported": 0, "failed": 0, "over_budget": 0, "not_attempted": 0}
    out["members"] = members
    budget = Budget(args["max_member_bytes"], args["max_total_bytes"], args["max_ratio"])
    out["budgets"] = {"max_member_bytes": budget.member, "max_total_bytes": budget.total, "max_members": args["max_members"], "max_ratio": budget.ratio,
                      "max_seconds": ctx.seconds}
    parts = ctx.page("parts")
    targets = ctx.page("external_targets", args["external_limit"])
    out["code_related_parts"] = []
    out["external_targets"] = []
    relationship_parts = {"read": 0, "failed": 0, "internal_relationships": 0}
    out["relationship_parts"] = relationship_parts
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
        window = Window(fh, end["eocd_at"] + 22, end["eocd_at"] + 20)
        try:
            archive = zipfile.ZipFile(io.BufferedReader(window))
        except Exception as exc:
            raise Stop("the archive will not open (%s: %s)" % (type(exc).__name__, scrub(str(exc))), out)
        names, seen = set(), {}
        extract_to = args["extract_to"]
        if extract_to is not None:
            try:
                os.makedirs(extract_to, exist_ok=True)
            except OSError as exc:
                fail("extract_to could not be created: %s" % describe(exc), status="failed")
        with archive:
            infos = archive.infolist()
            if len(infos) != total:
                ctx.problem("the end record declares %d member%s and the central directory holds %d" % (total, "" if total == 1 else "s", len(infos)))
            for index, info in enumerate(infos):
                if index >= args["max_members"]:
                    members["not_attempted"] = len(infos) - index
                    ctx.limit_hit("%d members are past max_members (%d): not listed, not read" % (len(infos) - index, args["max_members"]))
                    break
                if ctx.expired("the member loop"):
                    members["not_attempted"] = len(infos) - index
                    break
                members["listed"] += 1
                name = info.filename
                lowered = name.lower()
                names.add(lowered)
                seen[name] = seen.get(name, 0) + 1
                shown = member_name(name, ctx)
                row = {"name": shown, "bytes": info.file_size, "compressed": info.compress_size, "method": info.compress_type,
                       "modified": "%04d-%02d-%02dT%02d:%02d:%02d" % info.date_time}
                if shown != name:
                    row["name_withheld"] = True
                if info.flag_bits & 0x1:
                    row["encrypted"] = True
                    members["flagged_encrypted"] += 1
                code_related = any(part in lowered for part in CODE_PARTS)
                if code_related:
                    row["name_matches_code_part"] = True
                    out["code_related_parts"].append(shown)
                if code_related and extract_to is not None:
                    extract_member(archive, info, index, extract_to, budget, members, ctx, row, shown != name)
                if lowered.endswith(".rels"):
                    read_relationships(archive, info, shown, name, budget, members, relationship_parts, targets, out, ctx, row)
                parts.add(row)
    for name, count in seen.items():
        if count > 1:
            ctx.problem("the member name %s appears %d times: an OPC package has one part of each name, and readers resolve a repeated one differently" % (shown_path(name), count))
    if members["flagged_encrypted"]:
        ctx.problem("%d member%s marked encrypted in the directory: %s contents %s not examined" % (
            members["flagged_encrypted"], " is" if members["flagged_encrypted"] == 1 else "s are", "its" if members["flagged_encrypted"] == 1 else "their",
            "is" if members["flagged_encrypted"] == 1 else "are"))
    if "word/document.xml" in names:
        out["kind"] = "Word"
    elif any(n.startswith("xl/") for n in names):
        out["kind"] = "Excel"
    elif any(n.startswith("ppt/") for n in names):
        out["kind"] = "PowerPoint"
    else:
        out["kind"] = "a ZIP with no word/, xl/ or ppt/ part names"
    out["opc_markers"] = {"[Content_Types].xml": "[content_types].xml" in names, "_rels/.rels": "_rels/.rels" in names}
    out["coverage"] = {"structures_read": ZIP_READ, "structures_not_read": ZIP_NOT_READ}
    if extract_to is not None:
        out["extraction_note"] = ("Only the members whose names match a code-related pattern were extracted; the pattern is a name test, "
                                  "not a content check, and no other member was written.")
        out["extracted_parts_may_contain_secrets"] = True
    return out


def count_unreadable(members, ctx, kind, shown, reason):
    members[kind] += 1
    if kind in ("over_budget", "not_attempted"):
        ctx.limit_hit("%s: %s" % (shown, reason))
    else:
        ctx.problem("%s: %s" % (shown, reason))


def extract_member(archive, info, index, extract_to, budget, members, ctx, row, withheld):
    shown = row["name"]
    target = fd = None
    try:
        target, fd = extraction_target(extract_to, index, info.filename, withheld)
    except OSError as exc:
        ctx.problem("%s: the part could not be created in extract_to (%s)" % (shown, describe(exc)))
        members["failed"] += 1
        return
    kept = False
    try:
        with os.fdopen(fd, "wb") as out_fh:
            fd = None
            for chunk in stream_member(archive, info, budget):
                out_fh.write(chunk)
        kept = True
    except Unreadable as exc:
        count_unreadable(members, ctx, exc.kind, shown, exc.reason)
        row["extraction"] = exc.kind
    except OSError as exc:
        members["failed"] += 1
        ctx.problem("%s: writing the part failed (%s)" % (shown, describe(exc)))
        row["extraction"] = "failed"
    finally:
        if fd is not None:
            os.close(fd)
        if not kept:
            try:
                os.unlink(target)
            except OSError:
                pass
    if kept:
        members["read"] += 1
        row["extracted_to"] = shown_path(target)


def read_relationships(archive, info, shown, name, budget, members, relationship_parts, targets, out, ctx, row):
    def handle(rel):
        mode = rel.get("TargetMode")
        if mode == "External":
            serial = targets.total + 1
            finding_id = "T%06d" % serial
            raw = rel.get("Target", "")
            trow = {"finding_id": finding_id, "part": shown, "relationship_id": scrub(rel.get("Id", ""), "names"),
                    "type": scrub(rel.get("Type", "").rsplit("/", 1)[-1], "names"), "target": redact_url(raw), "target_length": len(raw)}
            targets.add(trow)
            if len(out["external_targets"]) < ctx.limit:
                out["external_targets"].append(trow)
            ctx.values.add(finding_id, {"part": name, "relationship_id": rel.get("Id", ""), "type": rel.get("Type", "")}, raw)
        elif mode not in (None, "Internal"):
            ctx.problem("%s: relationship %s has a TargetMode of %s, neither Internal nor External: not counted as external"
                        % (shown, scrub(rel.get("Id", ""), "names"), scrub(mode, "names")))
        else:
            relationship_parts["internal_relationships"] += 1

    try:
        notes = parse_relationships(stream_member(archive, info, budget), handle)
    except Unreadable as exc:
        count_unreadable(members, ctx, exc.kind, shown, exc.reason)
        relationship_parts["failed"] += 1
        row["relationships"] = exc.kind
        return
    except DoctypeRefused:
        ctx.problem("%s: the part contains a DOCTYPE, which is refused: it was not parsed" % shown)
        relationship_parts["failed"] += 1
        members["failed"] += 1
        row["relationships"] = "doctype_refused"
        return
    except xml.parsers.expat.ExpatError as exc:
        ctx.problem("%s: the part is not well-formed XML (%s): the relationships before the error are listed" % (shown, xml.parsers.expat.ErrorString(exc.code)))
        relationship_parts["failed"] += 1
        members["failed"] += 1
        row["relationships"] = "not_well_formed"
        return
    members["read"] += 1
    relationship_parts["read"] += 1
    row["relationships"] = "read"
    if notes["other_namespace"]:
        ctx.problem("%s: %d Relationship element(s) are not in the package-relationships namespace and were not read" % (shown, notes["other_namespace"]))
    if notes["over_cap"]:
        ctx.limit_hit("%s: more than %d relationships: the rest were not read" % (shown, MAX_RELATIONSHIPS))


class Stop(Exception):
    def __init__(self, message, partial=None):
        Exception.__init__(self, message)
        self.message, self.partial = message, partial or {}


# --- PDF, RTF, OLE ----------------------------------------------------------------------------------------------------------------

def probe_pdf(blob, ctx):
    out = {"container": "PDF"}
    head = blob[:HEAD_BYTES]
    m = re.search(rb"%PDF-(\d\.\d)", head)
    if m:
        out["pdf_header"] = {"version": m.group(1).decode("ascii"), "offset": m.start()}
    else:
        ctx.problem("no %%PDF- header line in the first %d bytes" % HEAD_BYTES)
    offsets = ctx.page("pdf_marker_offsets", 500)
    markers = []
    present = {}
    capped = False
    stopped = False
    for kw, rx, what in PDF_RX:
        count, first = 0, []
        if stopped:
            present[kw] = 0
            continue
        for hit in rx.finditer(blob):
            count += 1
            if len(first) < MARKER_OFFSETS:
                first.append(hit.start())
            if offsets.total < OFFSETS_CAP:
                offsets.add({"keyword": kw.decode("ascii"), "offset": hit.start()})
            elif not capped:
                capped = True
                ctx.limit_hit("marker offsets: the file lists the first %d offsets; the counts go on past them" % OFFSETS_CAP)
            if count % 4096 == 0 and ctx.expired("the marker scan"):
                stopped = True
                break
        present[kw] = count
        if count:
            markers.append({"keyword": kw.decode("ascii"), "count": count, "first_offsets": first, "what": what})
    # Names of filters that hide the stream behind them from a byte search: markers inside such a stream are not seen here.
    filtered = 0
    if not stopped:
        for _hit in PDF_FILTER.finditer(blob):
            filtered += 1
            if filtered % 65536 == 0 and ctx.expired("the filter count"):
                break
    out["markers"] = markers
    out["encrypt_marker_present"] = present[b"/Encrypt"] > 0
    out["object_stream_markers"] = present[b"/ObjStm"]
    out["filtered_streams"] = filtered
    if filtered or present[b"/ObjStm"]:
        ctx.problem("%d filter name(s) that hide a stream's content (FlateDecode, LZW, ASCII85, ASCIIHex, RunLength, Crypt) and %d object-stream marker(s): "
                    "the streams were not decoded, so a marker inside one is not in this answer" % (filtered, present[b"/ObjStm"]))
    out["coverage"] = {"structures_read": PDF_READ, "structures_not_read": PDF_NOT_READ}
    out["marker_note"] = ("Markers are byte-pattern observations with the offsets of the first occurrences. Keywords inside compressed "
                          "object streams, names written with #-escapes and other encodings are not found: a zero count is not an absence.")
    return out


def probe_rtf(blob, ctx):
    out = {"container": "RTF"}
    offsets = ctx.page("rtf_objdata_offsets")
    count = 0
    capped = False
    for hit in RTF_OBJDATA.finditer(blob):
        count += 1
        if offsets.total < OFFSETS_CAP:
            offsets.add(hit.start())
        elif not capped:
            capped = True
            ctx.limit_hit("object offsets: the file lists the first %d offsets; the count goes on past them" % OFFSETS_CAP)
        if count % 4096 == 0 and ctx.expired("the object scan"):
            break
    classes, seen, markers = [], set(), 0
    for m in RTF_OBJCLASS.finditer(blob):
        markers += 1
        name = scrub(m.group(1).decode("ascii"), "names")
        if name not in seen:
            if len(seen) >= MAX_CLASSES:
                continue
            seen.add(name)
            classes.append(name)
        if markers % 4096 == 0 and ctx.expired("the class scan"):
            break
    if len(seen) >= MAX_CLASSES:
        ctx.limit_hit("classes: the first %d distinct class names are listed" % MAX_CLASSES)
    out["objdata_markers"] = count
    out["object_offsets"] = offsets.page
    out["objclass_markers"] = markers
    out["classes"] = sorted(classes)
    out["coverage"] = {"structures_read": RTF_READ, "structures_not_read": RTF_NOT_READ}
    out["marker_note"] = ("RTF has no container: object data is hex-encoded inline, which a plain strings search does not decode. "
                          "Each offset is the start of one \\objdata control word; the data itself is not read.")
    return out


def probe_ole(blob, ctx):
    out = {"container": "OLE compound file", "markers": []}
    rows = [(b"VBA", "ASCII", "VBA"), ("VBA".encode("utf-16-le"), "UTF-16LE", "VBA"),
            (b"_VBA_PROJECT", "ASCII", "_VBA_PROJECT"), ("_VBA_PROJECT".encode("utf-16-le"), "UTF-16LE", "_VBA_PROJECT")]
    for needle, encoding, label in rows:
        at = blob.find(needle)
        out["markers"].append({"marker": label, "encoding": encoding, "found": at >= 0, "first_offset": at if at >= 0 else None})
    out["coverage"] = {"structures_read": OLE_READ, "structures_not_read": OLE_NOT_READ}
    out["marker_note"] = ("A marker is a byte search over the whole file, not a directory entry: stream names in a compound file are "
                          "UTF-16LE, and a match can sit in ordinary data. The macro project, if there is one, is not parsed here.")
    return out


# --- the call ---------------------------------------------------------------------------------------------------------------------------

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


def main():
    try:
        args = json.load(sys.stdin)
    except ValueError as exc:
        fail("arguments are not valid JSON", reason=str(exc))
    if not isinstance(args, dict):
        fail("arguments must be a JSON object")
    path = args.get("path")
    if not isinstance(path, str) or not path:
        fail("path is required: a document to look inside")
    why_not = file_problem(path)
    if why_not:
        fail(why_not, path=path)
    extract_to = args.get("extract_to")
    if extract_to is not None and (not isinstance(extract_to, str) or not extract_to):
        fail("extract_to must be a non-empty path when supplied")
    if extract_to is not None:
        extract_to = resolve_output(extract_to, "extract_to")
    write_values = args.get("write_values", False)
    if not isinstance(write_values, bool):
        fail("write_values must be true or false")
    cfg = {
        "extract_to": extract_to,
        "max_member_bytes": positive_int(args, "max_member_bytes", DEFAULT_MEMBER),
        "max_total_bytes": positive_int(args, "max_total_bytes", DEFAULT_TOTAL),
        "max_members": positive_int(args, "max_members", DEFAULT_MEMBERS, MAX_DIRECTORY_ENTRIES),
        "max_ratio": positive_int(args, "max_ratio", DEFAULT_RATIO),
        "external_limit": positive_int(args, "limit", DEFAULT_LIMIT),
    }
    seconds = positive_int(args, "max_seconds", DEFAULT_SECONDS, MAX_SECONDS)
    try:
        values = SecretValues(write_values)
    except SecretValuesRefused as exc:
        fail(str(exc), write_values="refused", written=False)
    VALUES[0] = values

    size = os.path.getsize(path)
    ctx = Ctx(os.path.realpath(path), cfg["external_limit"], values, seconds)
    shown = shown_path(path)
    if shown != path:
        ctx.names.add(path, shown, "input_path")
    try:
        with open(path, "rb") as fh:
            head = fh.read(HEAD_BYTES)
    except OSError as exc:
        values.close()
        fail("the file could not be opened: %s" % describe(exc), path=path)
    if not head:
        values.close()
        fail("the file is empty", path=path)
    body, stop = {}, None
    try:
        if head[:4] in (b"PK\x03\x04", b"PK\x05\x06"):
            try:
                body = probe_zip(path, size, ctx, cfg)
            except Stop as exc:
                stop = exc
        else:
            with open(path, "rb") as fh:
                blob = mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_READ)
                try:
                    if head[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":
                        body = probe_ole(blob, ctx)
                    elif b"%PDF-" in head:
                        body = probe_pdf(blob, ctx)
                    elif b"{\\rtf" in head:
                        body = probe_rtf(blob, ctx)
                        body["rtf_header_offset"] = head.find(b"{\\rtf")
                    else:
                        values.close()
                        fail("this is not a container this tool reads", status="unsupported", path=path, head_hex=head[:8].hex(),
                             reads=["OOXML or ZIP", "PDF", "RTF", "OLE compound file"])
                finally:
                    blob.close()
    finally:
        values.close()
        ctx.names.close()

    tables = {}
    for name, page in ctx.pages.items():
        tables[name] = page.finish()
        if page.not_written:
            ctx.problem("the whole %s table could not be written to a file: %s" % (name, page.not_written))
    if ctx.names.error:
        ctx.problem("the real names behind the withheld ones could not be kept: %s" % ctx.names.error)
    if "parts" in ctx.pages:
        body["parts"] = ctx.pages["parts"].page
    extension = os.path.splitext(path)[1].lower().lstrip(".")
    disagreement = None
    if body.get("code_related_parts") and extension in ("docx", "xlsx", "pptx"):
        disagreement = {"extension": extension, "code_related_part": body["code_related_parts"][0],
                        "text": ("The filename extension and the detected code-related parts disagree; renaming history, application "
                                 "acceptance and execution are not established.")}
    truncated = any(p["truncated"] for p in tables.values())
    members = body.get("members")
    unread = bool(members and (members["encrypted"] or members["unsupported"] or members["failed"] or members["over_budget"] or members["not_attempted"]))
    head_out = {"tool": TOOL, "parser": PARSER, "path": shown, "bytes": size, "extension": scrub(extension, "names") or None}
    if stop is not None:
        print(json.dumps({**head_out, **stop.partial, "status": "failed", "status_basis": stop.message, "error": stop.message,
                          "problems": ctx.problems, "limits_hit": ctx.limits, "withheld": COUNTS, "secret_values": values.summary(), "note": NOTE}, indent=2))
        raise SystemExit(1)
    status = "partial" if (ctx.problems or ctx.limits or unread) else "complete"
    basis = ("every structure this tool reads was read in full" if status == "complete" else
             "%d problem(s), %d limit(s)%s: see `problems`, `limits_hit` and `members`" % (
                 len(ctx.problems), len(ctx.limits), "; some members were not read" if unread else ""))
    marker_note = body.pop("marker_note", None)
    result = {**head_out, **body, "extension_content_disagreement": disagreement, "status": status, "status_basis": basis,
              "problems": ctx.problems, "limits_hit": ctx.limits, "tables": tables, "truncated": truncated,
              "withheld": COUNTS, "secret_values": values.summary(), "note": NOTE + (" " + marker_note if marker_note else "")}
    if ctx.names.shown:
        result["withheld_names_file"] = ctx.names.shown
        result["withheld_names_note"] = ("The real name behind every name withheld here is in this file (mode 0600, always written when a name is withheld): "
                                         "run the job with secret_output: true.")
    if ctx.problems_dropped:
        result["problems_not_listed"] = ctx.problems_dropped
    if values.enabled or COUNTS["urls"] or COUNTS["names"] or COUNTS["text"]:
        result["withheld_note"] = ("Credentials and token-shaped text in a URL or a name are withheld from this answer; the URL's length is kept. "
                                   "The whole target is in the values file when write_values was asked for in a secret_output job.")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except Exception as exc:  # never a traceback and never a clean answer for a failure
        fail("unexpected failure: %s" % (describe(exc) if isinstance(exc, OSError) else "%s: %s" % (type(exc).__name__, scrub(str(exc)))))
