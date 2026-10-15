#!/usr/bin/env python3
"""Read the descriptors of a set of virtual-disk files and say how they chain: which file names which as its parent,
whether the parent is there, whether the identity the child recorded is the identity the parent carries, which extents
a descriptor needs and which are missing, and which markers a consolidation or an unclean close may leave behind.

The formats read, from their public descriptions, and no others (a file of any other kind is counted and named, never
guessed at):

    VMware VMDK   a text descriptor (# Disk DescriptorFile: CID, parentCID, parentFileNameHint, createType, extent lines)
                  or the descriptor embedded in a sparse extent (KDMV header, version 1 to 3). A COWD extent is
                  recognised and not read.
    VMware        .vmx (the disk files the configuration names) and .vmsd (the snapshot database), read for the names
                  they hold, to hold the descriptors against.
    VHD           the footer (conectix), the dynamic-disk header (cxsparse) of a dynamic or differencing disk, the
                  parent's unique id, name and locators
    VHDX          the file identifier, the two headers (CRC-32C, sequence number, GUIDs, log GUID), the region table, the
                  metadata table, the file parameters, the virtual disk id and the parent locator. A child's parent_linkage
                  is held against the parent's DataWriteGuid (of its current header), which is what MS-VHDX says it
                  records; the VirtualDiskId is shown as information
    QCOW2         versions 2 and 3: the header, the backing file name, the header extensions, the feature bits, and the
                  internal snapshot table

What it is and is not. It is a reading of headers and descriptors, not of disk content: no sector of a disk is
interpreted, no extent is opened but to measure it, and nothing is mounted, converted, repaired or merged. A chain it
calls complete is a chain whose named parents are present in the set and read, whose recorded identities agree, and
whose extents and data files are in the set; any other chain says which of those failed first. It is not a
disk that boots, and it says nothing about what the parent held when the child was made (QCOW2 records no identity of its
backing file at all). A marker is a candidate with the observation beside it; it is not a verdict. The layouts are
implemented from the format descriptions; they have not been checked against files made by every product or version, and
a version this tool does not know is reported and not read.

qemu-img is run only when asked (qemu_img: auto or require), once per image of the set with the format fixed and never
with --backing-chain, and its answer is kept beside the native reading and never replaces it; a run that fails or times
out makes the answer partial. A VMDK text descriptor and a QCOW2 image with an external data file are not given to it,
because qemu-img opens the files those name, nor is an extent another descriptor names. Nothing in the set is executed, and a name inside a file is looked up among
the files given, never opened by this tool: a parent named outside the set is reported as missing.

SENSITIVE OUTPUT. Names, hints, snapshot names and descriptions are shown after the shape check of the shared block:
a token-shaped run or user-info is withheld, a long text is shown cut with its whole length, and the original goes to
one private file only when write_text is asked for, in a job. Every key and value of the answer and of its paging files
passes the one way out (SHARED BOUNDARY), which withholds by shape again and checks what it wrote. A VM configuration can hold a password or a token under a
key this tool does not read: only the names of the disk files and the snapshot database's names are taken from it.
"""
import collections
import datetime
import errno
import itertools
import json
import math
import os
import posixpath
import re
import secrets
import signal
import stat
import struct
import subprocess
import sys
import tempfile
import time
import unicodedata
import uuid
from pathlib import Path

TOOL = "snapshot_chain_check"
PARSER = "snapshot_chain_check/1"
DEFAULT_LIMIT = 200
DEFAULT_SECONDS = 50.0          # the manifest allows 60
MAX_SECONDS = 50.0
MAX_DESCRIPTOR = 1 << 20        # a descriptor, embedded or alone, is read to this many bytes
MAX_DESC_LINES = 20000
MAX_EXTENTS = 10000             # extent lines kept per descriptor; the rest are counted
MAX_CONFIG_BYTES = 16 << 20     # a .vmx or .vmsd over this is named and not read
MAX_CONFIG_LINE = 1 << 16
MAX_CONFIG_LINES = 500000
MAX_SNAPSHOT_ENTRIES = 20000    # distinct snapshotN indexes kept from one .vmsd; the rest are counted
DEFAULT_MAX_SNAPSHOTS = 100000  # internal QCOW2 snapshots read from one image
MAX_CHAIN_SHOWN = 50
MAX_CONFIG_ENTRIES_TOTAL = 100000  # snapshot entries (and disk entries) kept across every .vmsd (and .vmx) of one run
CREATE_TYPES = {"monolithicSparse", "monolithicFlat", "twoGbMaxExtentSparse", "twoGbMaxExtentFlat", "fullDevice", "partitionedDevice", "vmfs", "vmfsSparse",
                "vmfsEagerZeroedThick", "vmfsThin", "vmfsRaw", "vmfsRawDeviceMap", "vmfsPassthroughRawDeviceMap", "streamOptimized", "seSparse", "custom"}
KNOWN_DDB = ("ddb.adapterType", "ddb.virtualHWVersion", "ddb.toolsVersion", "ddb.thinProvisioned", "ddb.longContentID", "ddb.uuid")
VOCABULARY = CREATE_TYPES   # words the way out shows as they are (see SHARED BOUNDARY)
WITHHELD_CONFIG_NOTE = "other keys of a .vmx are not read: they can hold a password or a token"

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
# BEGIN SHARED COMMON
# The same text is in virtualization_inventory, snapshot_chain_check and backup_audit_normalise (a tool is standalone, none
# imports another); tests/pack-virtualization-shared.test.ts holds the copies equal. Arguments, the status every answer
# carries, lossless paging, and the one place a withheld text is kept when, and only when, it was asked for.


def in_job():
    return bool(os.environ.get("JOB_ID") and os.environ.get("OUT"))


def describe(exc):
    """An exception as text for an answer: its type and errno name, and its message withheld by shape (the way out's whole
    rules, so that nothing they would take is split first), never cut."""
    code = errno.errorcode.get(exc.errno, "") if getattr(exc, "errno", None) else ""
    return seal_head("%s%s: %s" % (type(exc).__name__, " " + code if code else "", getattr(exc, "strerror", None) or str(exc)), "text")


PAGING_OPEN = []        # the paging files being written (LosslessPage objects with a temporary file open)


def paging_left():
    """Close the paging files a stop leaves open and keep what they hold under a name that says so (`<name>.partial`): their
    rows were sealed as they were written. The names, as the answer shows them."""
    left = []
    for page in list(PAGING_OPEN):
        try:
            shown = page.abandon()
        except Exception:  # noqa: BLE001 - one file that cannot be closed must not hide the others
            shown = None
        if shown:
            left.append(shown)
    return left


def fail(message, **extra):
    """An error answer: JSON, exit 1, the same `status` every answer of this pack carries, through the one way out."""
    left = paging_left()
    if left:
        extra["paging_files_left"] = left
        extra["paging_files_note"] = "the rows written before the stop, sealed as they were written, kept under the name that says so"
    print(answer_text({"error": message, "tool": TOOL, "status": "failed", "status_basis": "the tool stopped with an error (see error)", **extra}))
    raise SystemExit(1)


def stop_word(signum):
    """The tool's last word when SIGTERM, SIGINT or SIGHUP ends it: one JSON answer through the one way out, naming the signal
    and any paging file it leaves. If the answer cannot be made (the signal came in the middle of the way out itself), a short
    one that says so."""
    name = {signal.SIGTERM: "SIGTERM", signal.SIGINT: "SIGINT", signal.SIGHUP: "SIGHUP"}.get(signum, "signal %d" % signum)
    left = []
    try:
        left = paging_left()
        print(answer_text({"tool": TOOL, "parser": PARSER, "status": "partial",
                           "status_basis": "the tool was stopped by %s before it finished: nothing after the stop was read or written" % name,
                           "stopped_by_signal": name, "paging_files_left": left,
                           "paging_files_note": "the rows written before the stop, sealed as they were written, kept under the name that says so" if left else "no paging file was open"}))
    except BaseException as exc:  # noqa: BLE001 - the last word is best effort, and never silent
        print(json.dumps({"tool": TOOL, "parser": PARSER, "status": "partial", "stopped_by_signal": name, "paging_files_left": left,
                          "status_basis": "the tool was stopped by %s; the full last word could not be made (%s)" % (name, type(exc).__name__)}))
    sys.stdout.flush()                      # the caller leaves with os._exit, which flushes nothing


def install_stop_handlers():
    """SIGTERM, SIGINT and SIGHUP: the last word, then exit 128 plus the signal number (snapshot_chain_check, which runs a program,
    gives its last word to the process block's handler instead)."""
    def on_signal(signum, _frame):
        try:
            stop_word(signum)
        except BaseException:  # noqa: BLE001 - a last word is best effort
            pass
        os._exit(128 + signum)
    for signum in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(signum, on_signal)


def read_args():
    try:
        raw = sys.stdin.buffer.read(8 << 20 | 1)
        if len(raw) > 8 << 20:
            fail("arguments are larger than 8 MiB: pass a list of files, not their contents")
        args = json.loads(raw.decode("utf-8") or "{}")
    except (ValueError, UnicodeDecodeError) as exc:
        fail("arguments are not valid JSON", reason=describe(exc))
    if not isinstance(args, dict):
        fail("arguments must be a JSON object")
    return args


MAX_ARG_STRING = 8192


def want_str(args, key, required=None, maximum=MAX_ARG_STRING):
    value = args.get(key)
    if value is None:
        if required:
            fail(required)
        return None
    if not isinstance(value, str):
        fail("%s must be a string" % key)
    if required and not value:
        fail(required)
    if len(value) > maximum:
        fail("%s is longer than %d characters" % (key, maximum))
    return value


def want_str_list(args, key, maximum=100000):
    value = args.get(key)
    if value is None:
        return []
    if not isinstance(value, list) or not all(isinstance(x, str) and x and len(x) <= MAX_ARG_STRING for x in value):
        fail("%s must be a list of non-empty strings of at most %d characters" % (key, MAX_ARG_STRING))
    if len(value) > maximum:
        fail("%s holds more than %d entries: pass a directory as root instead" % (key, maximum))
    return value


def want_flag(args, key):
    value = args.get(key, False)
    if not isinstance(value, bool):
        fail("%s must be true or false" % key)
    return value


def want_int(args, key, default, minimum, maximum):
    value = args.get(key, default)
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum or value > maximum:
        fail("%s must be an integer from %d to %d" % (key, minimum, maximum))
    return value


def want_seconds(args, key, default, maximum):
    """A time budget: a finite number above zero and no more than `maximum` (NaN and Infinity are not budgets)."""
    value = args.get(key, default)
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value <= 0 or value > maximum:
        fail("%s must be a number of seconds above 0 and at most %d" % (key, maximum))
    return float(value)


def status_of(complete, failed, basis_complete, basis_partial, basis_failed):
    """The `status` every answer of this pack carries, with the reason for it: complete (everything the request asked
    for was read and nothing was left out), partial (some of it was, and the answer names what was not) or failed."""
    if failed:
        return {"status": "failed", "status_basis": basis_failed}
    if complete:
        return {"status": "complete", "status_basis": basis_complete}
    return {"status": "partial", "status_basis": basis_partial}


class Overtime(Exception):
    pass


class Clock:
    def __init__(self, seconds):
        self.deadline = time.monotonic() + seconds
        self.count = 0

    def check(self, every=1):
        self.count += 1
        if self.count % every == 0 and time.monotonic() > self.deadline:
            raise Overtime()

    def left(self):
        return max(0.0, self.deadline - time.monotonic())


def blen(text):
    return len(text.encode("utf-8", "surrogatepass"))


def decode(data):
    """Bytes as text with no byte lost: an undecodable byte is a lone surrogate, which a JSON escape writes and which
    encodes back to the byte."""
    return data.decode("utf-8", "surrogateescape")


# Lossless paging: the page an agent reads stays small, and when there are more rows the whole result is written as JSON
# Lines under work/<agent>/tool-output (in a job, $OUT/tool-output) and named. The file name is random: it is never a
# digest of anything asked for (sixteen decimal digits), and the way out shows this exact name, registered here, as it is. Every row is sealed
# (the one way out, below) as it is written. A write that fails is an error answer naming the file, never a loss that
# goes unsaid.
class LosslessPage:
    def __init__(self, tool, key, limit):
        if isinstance(limit, bool) or not isinstance(limit, int) or limit < 1:
            raise ValueError("limit must be a positive integer")
        self.tool = re.sub(r"[^A-Za-z0-9_.-]", "_", tool)
        self.key = re.sub(r"[^A-Za-z0-9_.-]", "_", key)
        self.limit = limit
        self.page = []
        self.total = 0
        self._out = None
        self._tmp = None
        name = "%s-%s-%016d.jsonl" % (self.tool, self.key, secrets.randbelow(10 ** 16))
        job, out = os.environ.get("JOB_ID"), os.environ.get("OUT")
        if job and out:
            self.path = Path(out) / "tool-output" / name
            self.shown = "store/jobs/%s/out/tool-output/%s" % (re.sub(r"[^A-Za-z0-9_.-]", "_", job), name)
        else:
            agent = re.sub(r"[^A-Za-z0-9_.-]", "_", os.environ.get("AGENT_ID") or "tool")
            self.path = Path("work") / agent / "tool-output" / name
            self.shown = str(self.path)
        OWN_NAMES.update((self.shown, str(self.path)))     # this exact name, and no other of its shape, is shown as it is

    def _write(self, row):
        line = row_text(row, "pages/%s/all_results" % self.key)
        try:
            self._out.write(line)
            self._out.write("\n")
        except OSError as exc:
            fail("the whole result could not be written: %s" % describe(exc), paging_file=str(self.path))

    def add(self, row):
        self.total += 1
        if len(self.page) < self.limit:
            self.page.append(row)
            return
        if self._out is None:
            stops = {signal.SIGTERM, signal.SIGINT, signal.SIGHUP}
            was = signal.pthread_sigmask(signal.SIG_BLOCK, stops)       # a stop must not come between the file and its registration
            try:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                fd, name = tempfile.mkstemp(dir=self.path.parent, prefix=".%s-" % self.path.name)
                self._tmp = Path(name)
                self._out = os.fdopen(fd, "w", encoding="ascii", errors="backslashreplace")
                PAGING_OPEN.append(self)
            except OSError as exc:
                signal.pthread_sigmask(signal.SIG_SETMASK, was)
                fail("the whole result could not be written: the paging file cannot be created (%s)" % describe(exc), paging_file=str(self.path))
            signal.pthread_sigmask(signal.SIG_SETMASK, was)
            for kept in self.page:
                self._write(kept)
        self._write(row)

    def abandon(self):
        """A stop with the file open: the rows written so far are kept as `<name>.partial`; the name as the answer shows it."""
        if self._out is None or self._tmp is None:
            return None
        keep = self.path.with_name(self.path.name + ".partial")
        try:
            os.replace(self._tmp, keep)         # the name first: it is atomic and touches no file object
        except OSError:
            return None
        try:
            self._out.flush()
            self._out.close()
        except (OSError, RuntimeError, ValueError):
            pass                                # a write was in progress when the signal came in: what the system already holds is kept
        self._out = None
        if self in PAGING_OPEN:
            PAGING_OPEN.remove(self)
        OWN_NAMES.update((self.shown + ".partial", str(keep)))
        return self.shown + ".partial"

    def finish(self):
        result = {"matched": self.total, "returned": len(self.page), "truncated": self.total > len(self.page)}
        if self._out is not None:
            try:
                self._out.flush()
                os.fsync(self._out.fileno())
                self._out.close()
                os.replace(self._tmp, self.path)
                if self in PAGING_OPEN:
                    PAGING_OPEN.remove(self)
            except OSError as exc:
                fail("the whole result could not be written: %s" % describe(exc), paging_file=str(self.path))
            result["all_results"] = self.shown
            result["all_results_format"] = "JSON Lines, one complete row per line"
        return result


class TextRefused(Exception):
    pass


class TextFile:
    """Where the original of a withheld or shortened text goes when, and only when, the caller asked for it.

    The secret-safe output pattern of recovery_key_scan's SecretValues, for rows. With `enabled` false it writes
    nothing and `summary()` says so. Enabled, it is refused outside a job; inside one the file is created before
    anything is read (mode 0600, exclusively: a file or a link already at that name is refused by name) under $OUT, and
    the answer names it and says it may hold secrets. With nothing to keep it stays an empty file and says written: 0.
    """

    def __init__(self, name, enabled, what, flag="write_text"):
        self.enabled = enabled
        self.written = 0
        self.what = what
        self.flag = flag
        self._fh = None
        self.path = None
        self.shown = None
        if not enabled:
            return
        job, out = os.environ.get("JOB_ID") or "", os.environ.get("OUT") or ""
        if not (job and out):
            raise TextRefused("%s is refused outside a job: the originals written here would be an ordinary file, not a "
                              "sealed output. Run this as job_run tool=%s with secret_output: true, and ask again there. "
                              "Nothing was written." % (flag, TOOL))
        self.path = Path(out) / name
        self.shown = "store/jobs/%s/out/%s" % (re.sub(r"[^A-Za-z0-9_.-]", "_", job), name)
        OWN_NAMES.update((self.shown, str(self.path)))
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            fd = os.open(str(self.path), os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        except FileExistsError:
            raise TextRefused("the values file already exists: %s" % name)
        except OSError as exc:
            raise TextRefused("the values file could not be created (%s)" % describe(exc))
        self._fh = os.fdopen(fd, "wb")

    def add(self, row):
        if self._fh is None:
            return
        try:
            self._fh.write(json.dumps(row, default=str).encode("ascii") + b"\n")
        except OSError as exc:
            fail("the values file could not be written (%s)" % describe(exc))
        self.written += 1

    def close(self):
        if self._fh is not None:
            try:
                self._fh.flush()
                os.fsync(self._fh.fileno())
                self._fh.close()
            except OSError as exc:
                fail("the values file could not be closed (%s)" % describe(exc))
            self._fh = None

    def summary(self):
        if not self.enabled:
            return {"requested": False, "written": 0, "file": None, "contains_text_that_may_hold_secrets": False,
                    "hint": "Nothing withheld or shortened is kept. %s: true, in a job run with secret_output: true, keeps the "
                            "original of each in a private file under $OUT." % self.flag}
        return {"requested": True, "written": self.written, "file": self.shown,
                "contains_text_that_may_hold_secrets": self.written > 0, "format": self.what}


class Shown(str):
    """A string that has been through the shape check: it is not checked again."""
    judged = True


# An open-ended authority or name:secret run at the point where a long text was cut might have its user-info separator beyond
# the cut, and a run of name characters the cut ends might be the head of a token: each is withheld whole.
_OPEN_AUTHORITY = re.compile(r"(?<=//)[^/?#\s]*$")
_OPEN_BARE = re.compile(r"[^\s/@:<>]{1,64}:[^\s/@<>]*$")
_RUN_CHARS = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_+%/=.:@-")


def cut_safely(text, limit):
    """`text` cut to at most `limit` characters (plus a marker), never leaving the head of a run the cut split: a text
    is withheld by shape BEFORE it is cut, and what the cut leaves open is withheld whole, not shown in part."""
    if len(text) <= limit:
        return text
    head = text[:limit]
    if limit > 0 and text[limit] in _RUN_CHARS and head[-1] in _RUN_CHARS:      # the cut fell inside a run: the run's head is withheld whole
        start = limit
        while start > 0 and head[start - 1] in _RUN_CHARS:
            start -= 1
        head = head[:start] + _withheld("open run at a cut", limit - start, "cut")
    head = _OPEN_AUTHORITY.sub(lambda m: _withheld("userinfo", len(m.group()), "text"), head)
    return _OPEN_BARE.sub(lambda m: _withheld("userinfo", len(m.group()), "text"), head)


def brief(text, limit=300):
    """A message from a library or a program, withheld by shape whole and then cut safely: never cut first."""
    return cut_safely(seal_head(text if isinstance(text, str) else str(text), "text"), limit)


class Shower:
    """Every string the answer shows a name, a path or a value of passes through here: token-shaped runs and user-info are
    withheld, a text over `limit` characters is shown cut with its whole length, and the original of what was changed goes
    to the values file when one was asked for (never anywhere else). Only the first EXAMINED characters of a long text are
    checked (the check is not linear in the length of an adversary's text): a run of name characters, an authority or a
    name:secret run that the EXAMINED cut leaves open is withheld whole before the shape check, so that no fragment of a
    token the cut split can be shown; the check runs on the whole examined text, and the shorter cut to `limit` comes
    after it and leaves no run open either."""

    EXAMINED = 4096

    def __init__(self, values, limit=512):
        self.values = values
        self.limit = limit
        self.changed = 0
        self.cut = 0

    def __call__(self, text, where=None, field=None):
        if text is None:
            return None
        if not isinstance(text, str):
            text = str(text)
        total = len(text)
        head = text
        if total > self.EXAMINED:
            head = cut_safely(text, self.EXAMINED)
        RUN["record"] = False                      # this call records the original itself
        try:
            shown = seal_text(head, "text", field, where)
        finally:
            RUN["record"] = True
        was_cut = total > self.EXAMINED
        if len(shown) > self.limit:
            shown = cut_safely(shown, self.limit)
            was_cut = True
        if was_cut:
            shown += "...(whole text: %d characters)" % total
            self.cut += 1
        if shown != text:
            self.changed += 1
            if self.values.enabled:
                self.values.add({"record_type": "original", "where": where, "field": field, "value": text})
        return Shown(shown)


def withheld_summary(shower):
    return {"strings_withheld_by_shape": dict(COUNTS), "strings_changed": shower.changed, "strings_shortened": shower.cut,
            "note": ("Names, paths and values the answer shows are checked by shape: a token-shaped run, user-info in a URL and a key "
                     "are withheld, and a string over %d characters is shown cut with its whole length. A secret that does not look "
                     "like a token (a short password in a name) is not recognised, so run the tool as a job with secret_output: true.") % shower.limit}
# END SHARED COMMON
# BEGIN SHARED BOUNDARY
# The same text is in virtualization_inventory, snapshot_chain_check and backup_audit_normalise; tests/pack-virtualization-
# shared.test.ts holds the copies equal. The one way out. Every key and every value of an answer, of an error answer and of
# every row a paging file holds is sealed when it is serialised, whatever code made it, in three layers:
#
# LAYER 1, an allow-list per field type. A string the evidence supplied is classified by the field it fills (the JSON key, or
# the label a call site gives the Shower; _FIELDS below): a name (VM, host, datastore, snapshot, network, key), a path or a file
# name, an identifier of a declared kind (GUID, VMFS volume id, naa./eui./t10./wwn- device ids, a VMware uuid, a MAC, a CID, a
# number), or a simple value (an enum word, a version, a time). It is shown as it is only when it fits the plain grammar of
# its type: printable letters, digits, space and . _ - ( ) + [ ] ' # , & ~ % $ (a path adds / \ { }, a drive or storage prefix
# and host:port), no `=`, no `@`, no `:` before a value, a bounded length (160 characters for a name, 96 for a simple value,
# 255 for each component of a path), no known token prefix, no named secret, and no run of 16 or more letters and digits that
# changes class (capitals, small letters, digits) as random text does, unless it is words or a well-formed identifier of a kind
# (a GUID in a Hyper-V file name, the volume id of /vmfs/volumes/<id>/, naa.<hex>, the name Windows gives a machine nobody named).
# Anything else is shown as <withheld: N bytes, field F>; a path is judged component by component, and when a component is
# withheld as a piece of a base64 key the key's other pieces next to it (across a `/`) are withheld with it. The original goes to the
# values file when one was asked for (write_text, a job). A key piece with something glued to it (`local:`, `[ds1] `, a quote, a
# JSON brace) is judged by the stretch of key at its end next to the `/`. An iqn. or t10. id is shown as an id only when what it holds
# is a name and not a stretch of random text. A name shorter than the run threshold is shown whatever it is: a short password used
# as a VM name is not recognised.
#
# LAYER 2, a deny-list, for every other string (a description, an annotation, an audit action or actor, a message, any text
# the tool wrote around a name). The string is first normalised by Unicode property, not by a list: characters of the
# categories Cf, Cc, Mn, Me, Cs, Co, Cn, Zl, Zp, the Hangul and half-width fillers and the escapes of any of them (\u2066,
# \x00) are taken out, and when that reading has something to withhold it is the one shown (a token split by bidi isolates,
# variation selectors, tag characters or combining marks is a token). Then, in linear time: user-info up to the last `@`
# before the host; the shared block's token rules and the shapes added here (a base64 key with its padding, a slashed run,
# the head of a prefixed token, a run of more than 18 digits, a PEM key); and the value after a name that says it is a secret,
# found ANYWHERE in the string (the secret word first, then what follows `=` or `:`; password, passwd, passphrase, pwd, secret,
# token, credential, api/access/account/private/secret/master/shared/signing/encryption key, authorization, bearer, dsn,
# webhook url, connection string, ssh key, snmp community, and pass, pw, auth, sig, sas, otp, psk, pin at the start of a word,
# in any case, glued or CamelCase, with up to two digits after the name: vncPassword=, adminPassword=, SecretAccessKey:,
# PGPASSWORD=, MYSQL_PWD=, sig=, cipassword:, password1=, pass_word:, and `--password <value>`, `-password <value>`, `--passphrase <value>`,
# `set password <value>`; a value in angle brackets is a value, unless it is a placeholder word: <redacted>, <password>). A name not in this list (a bare key, community, webhook or url; "the password is X") is not
# recognised. The rules are applied until they change nothing more.
#
# LAYER 3, the backstop, written apart from the two layers above (its own normaliser, patterns, named-secret search and
# class-transition check; none is reused): the serialised text is read back, and a string it still finds suspect is replaced
# by <withheld: N bytes>, its place and the check that fired are listed in boundary.replaced_at, and the answer is partial.
#
# Shown as they are by every layer: the exact names of the files this run made, a word of the tool's own closed vocabulary
# (VOCABULARY), a marker this block wrote. A run is bounded: the strings of one run share max_seconds (plus a short grace for
# the final answer) and a cap on the characters judged; past either, a string not judged before is withheld by its length and
# the answer is partial and names the stop. A string over 256 KiB is judged in its first 256 KiB and its rest is withheld.
BOUNDARY = {"withheld": 0, "replaced": 0, "where": [], "not_listed": 0, "by": collections.Counter()}
RUN = {"values": None, "deadline": None, "stop": None, "stopped_strings": 0, "chars": 0, "cap": 400000000, "record": True}
OWN_NAMES = set()               # the exact names of the files this run made, as the answer shows them
MAX_REPLACED_LISTED = 1000
MAX_ONE_STRING = 1 << 18


def bind_run(values, seconds):
    """The run's values file and clock: the strings of this run are judged within `seconds` (and a grace for the answer)."""
    RUN["values"] = values
    RUN["deadline"] = time.monotonic() + seconds


# ---- field types ---------------------------------------------------------------------------------------------------------
# A JSON key or a Shower label -> the type of what it holds (a digit run in a label stands for any number: ethernet0.address).
# A key that is not listed holds free text (layer 2): description, annotation, audit action, actor, message, a tool's own words.
_FIELDS = {}
for _kind, _names in (
    ("name", "name|display_name|domain_name|job|storage|storage name|networkName|ethernet#.networkName|snapshot name|disk key|displayName"
             "|current_parent_snapshot|snapshot_sections|snapshot|parent snapshot name|domain name|datastore|pool|vgname|thinpool|key"),
    ("path", "file|leaf_file|rel|root|links|special|unreadable|too_deep|lock directory|parent_hint|parentFileNameHint|parent name|parent_name|backing_file|backing_filename"
             "|external_data_file|parent_absolute_win32_path|parent_relative_path|parent_volume_path|disk_files|snapshot disk file|state_file|snapshot state file"
             "|extent file name|configuration_path|vmxCfgPath|datastore_hint|datastore path|nvram|disk file|volume|vm_state_volume|vmstate|path|named|export|special_sections|section|disk source|source_name|object"),
    ("id", "uid|snapshot uid|snapshot parent|snapshot id|parent_uid|uuid|bios_uuid|location_uuid|vcenter_instance_uuid|cid_raw|parent_cid_raw|CID|parentCID|entry_id|object_id|vmid"
           "|ddb.uuid|ddb.longContentID|current|lastuid|lastUID|numsnapshots|numSnapshots|source_id|own_id|leaf|base|child|ethernet#.address|ethernet#.generatedAddress|address"
           "|virtual_disk_id|unique_id|parent_unique_id|data_write_guid|file_write_guid|log_guid|parent_identity|parent_identity_2|recorded_by_child|carried_by_parent|descriptor_id"),
    ("simple", "create_type|createType|encoding|backing_format|backing format|native_snapshot|isNativeSnapshot|version|hardware_version|config_version|arch|bios|firmware|machine"
               "|os_type|virt_type|guest_os|guestOS|cores|vcpus|memory_mb|memory|device|device_type|deviceType|disk_format|mode|present|snapshot_mode|bus|backup|size|state|type"
               "|source_protocol|ddb.adapterType|ddb.virtualHWVersion|ddb.toolsVersion|ddb.thinProvisioned|time_raw|createTimeHigh|createTimeLow|create_time_high_raw"
               "|create_time_low_raw|extent type|type_raw|content|shared|disable|maxfiles|mkdir|is_mountpoint|nodes|ethernet#.virtualDev|ethernet#.present|ethernet#.addressType"),
):
    for _n in _names.split("|"):
        _FIELDS[_n] = _kind
# a value under these keys is judged as the key above it (the rows of an aggregate)
_INHERIT = frozenset(("top", "value"))
_IDENT_KINDS = frozenset(("name", "path", "id", "simple", "key"))
_DIGITS = re.compile(r"[0-9]+")


def field_kind(field):
    if not isinstance(field, str):
        return None
    kind = _FIELDS.get(field)
    if kind is None and field != "key" and any(c.isdigit() for c in field):
        kind = _FIELDS.get(_DIGITS.sub("#", field))
    return kind


# ---- the normalisers -------------------------------------------------------------------------------------------------------
# Layer 2's: characters of invisible or formatting categories, by Unicode property (not by a list of code points), and the
# fillers that render blank. The translate table is filled one code point at a time and bounded.
_STRIP_CATS = frozenset(("Cf", "Cc", "Mn", "Me", "Cs", "Co", "Cn", "Zl", "Zp"))
_FILLERS = frozenset((0x115F, 0x1160, 0x3164, 0xFFA0, 0x2800))


class _Strip(dict):
    def __missing__(self, o):
        if len(self) > 20000:
            self.clear()
        keep = unicodedata.category(chr(o)) not in _STRIP_CATS and o not in _FILLERS
        self[o] = o if keep else None
        return self[o]


_STRIP = _Strip()
# the escape of such a character written as text: \u2066, \U000e0041, \x00, \u{200b}
_ESCAPED = re.compile(r"(?<!\\)\\+(?:u([0-9A-Fa-f]{4})|U([0-9A-Fa-f]{8})|x([0-9A-Fa-f]{2})|u\{([0-9A-Fa-f]{1,6})\})")


def _unescape_invisible(m):
    try:
        c = chr(int(m.group(1) or m.group(2) or m.group(3) or m.group(4), 16))
    except (ValueError, OverflowError):
        return m.group(0)
    return "" if (unicodedata.category(c) in _STRIP_CATS or ord(c) in _FILLERS) else m.group(0)


_ESCAPED_PRINTABLE = re.compile(r"(?<!\\)\\+(?:x|u00)([2-7][0-9A-Fa-f])")


def _flat(text, nfkc=True, decode=True):
    """The text with invisible characters, and the escapes of such characters, taken out (and, past ASCII, in NFKC form); with
    `decode`, an escape of a printable ASCII character (\\x41, \\u0041) is the character, so that a token written in escapes is read."""
    if "\\" in text:
        text = _ESCAPED.sub(_unescape_invisible, text)
        if decode:
            text = _ESCAPED_PRINTABLE.sub(lambda m: chr(int(m.group(1), 16)), text)
    if text.isascii():
        if text.isprintable():
            return text
        return text.translate(_STRIP)
    out = text.translate(_STRIP)
    return unicodedata.normalize("NFKC", out) if nfkc and not out.isascii() else out


# ---- layer 2: the deny-list rules ----------------------------------------------------------------------------------------
# a GUID, or a VMFS volume id (8-8-4-12 hexadecimal digits), standing alone or after `_` as a Hyper-V file name puts it
_GUID_ALONE = re.compile(r"(?<![A-Za-z0-9+%/=-])(?:\{?[0-9A-Fa-f]{8}(?:-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}\}?|[0-9a-f]{8}-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{12})(?![A-Za-z0-9_+%/=-])")
_MARKER = re.compile(r"<(?:[a-z][a-z -]{0,40} )?withheld(?: \d+ characters|: \d+ bytes(?:, [a-z][a-z .]{0,60})?|: an integer of \d+ bits)>")
_CUT_NOTE = re.compile(r"\.\.\.\(whole text: \d+ characters\)$")
# name:secret@host, the secret running to the last `@` before the host (an `@` inside a password is part of it)
_ANY_USERINFO = re.compile(r"(?<![A-Za-z0-9._%+-])(?!mailto:)[^\s/@:<>\"'`]{1,64}:[^\s/<>\"'`]{1,128}(?=@[^\s/@<>\"'`]*(?:[\s/<>\"'`?#]|$))")
_SLASHED_RANDOM = re.compile(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{20,}={0,2}(?![A-Za-z0-9+=])")
_BASE64_KEY = re.compile(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{16,}={1,2}(?![A-Za-z0-9+=])")
_TOKEN_HEAD = re.compile(r"(?i:(?:AKIA|ASIA)[0-9A-Z]{4,}|gh[pousr]_[A-Za-z0-9]{4,}|github_pat_[A-Za-z0-9_]{4,}|xox[abeprs]-[A-Za-z0-9-]{6,}|eyJ[A-Za-z0-9_-]{10,}"
                         r"|glpat-[A-Za-z0-9_-]{4,}|(?:sk|rk|pk)_(?:live|test)_[A-Za-z0-9]{4,}|SG\.[A-Za-z0-9_-]{8,}(?:\.[A-Za-z0-9_-]*)?|AIza[0-9A-Za-z_-]{8,}"
                         r"|npm_[A-Za-z0-9]{8,}|pypi-[A-Za-z0-9_-]{8,}|shpat_[A-Za-z0-9]{8,}|dop_v1_[A-Za-z0-9]{8,}|ya29\.[A-Za-z0-9_-]{8,})")
# The value after a name that says it is a secret, found anywhere in the string: the secret word first (glued to whatever comes
# before it, in any case: vncPassword, adminpass, dbPwd; `pass` not after by, com, over, under, tres, encom, sur or im, so that
# bypass: and compass: are words), then `=` or `:` (quotes and a little space allowed), then the value and up to three more words
# of it. An error message's `token: line 3, column 5` is not a value. A value in angle brackets is a value, whatever it holds: only a
# placeholder word the tool knows (<redacted>, <password>, <secret>, <token>, <hidden>, <masked>, <value>, <your-password>, <***> ...) is
# not (_PLACEHOLDER).
_PLACEHOLDER = r"<(?i:redacted|hidden|masked|removed|omitted|secret|password|passwd|passphrase|pwd|pass|token|key|value|placeholder|empty|none|null|unset|your[ _-]?(?:password|secret|token|key)|\*{1,16})?>"
_NAMED_SECRET = re.compile(
    r"(?:(?i:pass[_-]?w(?:or)?d|passwd|passphrase|pwd|secret|token|credentials?|api[_-]?key|access[_-]?key|account[_-]?key|private[_-]?key|master[_-]?key"
    r"|shared[_-]?key|signing[_-]?key|encryption[_-]?key|secret[_-]?key|authorization|bearer|dsn|webhook[_-]?url|connection[_-]?string|ssh[_-]?key"
    r"|snmp[_-]?community|community[_-]?string)"
    r"|(?<![Bb]y)(?<![Cc]om)(?<![Oo]ver)(?<![Uu]nder)(?<![Tt]res)(?<![Ee]ncom)(?<![Ss]ur)(?<![Ii]m)(?i:pass)"
    r"|(?i:pw|auth|sig|sas|otp|psk|pin))s?[0-9]{0,2}(?:\\{0,3}[\"'])?[ \t]{0,2}[=:][ \t]{0,2}(?:\\{0,3}[\"'])?"
    r"((?!line[ \t]+[0-9])(?!" + _PLACEHOLDER + r")(?:<[^<>\"'\n]{0,200}>|[^\s\"'>;,&\\][^\s\"'<>;,&]*(?:[ \t]+[^\s\"'<>;,&=:]+){0,3}))")
_NAMED_FLAG = re.compile(r"(?<![\w-])--?(?i:passw(?:or)?d|passwd|pass(?:phrase)?|pwd|secret|token|api[-_]?key|access[-_]?key|client[-_]?secret|auth|bearer|psk)(?:=|[ \t]+)(?!-)(?!" + _PLACEHOLDER + r")([^\s\"']+)")
_NAMED_SET = re.compile(r"(?<![\w-])(?i:set|enable)[ \t]+(?i:passw(?:or)?d|secret|passphrase|token)[ \t]+(?:[0-9][ \t]+)?(?!" + _PLACEHOLDER + r")([^\s\"']+)")
_LONG_DIGITS = re.compile(r"(?<![0-9])[0-9]{19,}(?![0-9])")
_PRIVATE_KEY = re.compile(r"-----BEGIN [A-Z0-9 ]{0,40}PRIVATE KEY-----.*?(?:-----END [A-Z0-9 ]{0,40}PRIVATE KEY-----|$)", re.S)
# A string none of whose rules can match is passed without the slow path: every rule needs one of these.
_QUICK = re.compile(r"[A-Za-z0-9_+%/=-]{14,}|@|AKIA|ASIA|gh[pousr]_|github_pat_|xox[abeprs]-|sk-|eyJ|(?i:basic|bearer)\s|(?i:set|enable)[ \t]+(?i:pass|secret|token)|[0-9]{19}|[=:]|-(?i:pass|pwd|secret|token|api|access|client|auth|bearer|psk)|-----BEGIN")
_PIECE = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_+%-")
_DIGIT_PLUS = re.compile(r"[0-9+]")
_SEALED = {}


def _random_slashed(run):
    """A base64 run holding `/`: random when its letters change case as random text does, or digits sit among them."""
    if "/" not in run:
        return False
    flat = run.replace("/", "").rstrip("=")
    letters = [c for c in flat if c.isalpha()]
    if not (any(c.islower() for c in letters) and any(c.isupper() for c in letters)):
        return False
    if not any(c.isdigit() for c in flat):          # a key of letters only: long, and its case changes as random text does
        return len(letters) >= 24 and sum(1 for a, b in zip(letters, letters[1:]) if a.islower() != b.islower()) >= 0.45 * len(letters)
    flips = sum(1 for a, b in zip(letters, letters[1:]) if a.islower() != b.islower())
    packed = len(re.findall(r"(?<=[A-Za-z])[0-9]{1,3}(?=[A-Za-z])", flat))
    return len(letters) >= 14 and (flips >= 0.33 * len(letters) or (packed and flips >= 0.25 * len(letters))) or _token_run(flat)


def _outside(text, pattern, fn):
    """`fn` applied to the parts of `text` that `pattern` does not match; the matches are kept as they are."""
    out, last = [], 0
    for m in pattern.finditer(text):
        out.append(fn(text[last:m.start()]) if m.start() > last else "")
        out.append(m.group())
        last = m.end()
    out.append(fn(text[last:]) if last < len(text) else "")
    return "".join(out)


# The shared block's prefixed-token rule with one change: a JWT head starts where a run of name characters starts, so that a run
# of `eyJeyJeyJ...` with no dot is read once and not once for every `eyJ` in it (the shared pattern is quadratic there).
_PREFIXED_ONCE = re.compile(_PREFIXED.pattern.replace("|eyJ[A-Za-z0-9_-]{8,}", "|(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{8,}"))


def _shared_spans(text):
    """What the shared block's token_spans finds, in linear time: the same rules, but a flagged span takes the random-looking
    pieces next to it across a `/` by a reverse and a forward character scan that never reads a character twice (the shared
    grow loop slices and searches the text again for every piece)."""
    spans = [m.span() for m in _PREFIXED_ONCE.finditer(text)]
    for m in _RUN.finditer(text):
        if _token_run(m.group()):
            spans.append(m.span())
    for m in _SLASHED.finditer(text):
        run = m.group()
        if "/" in run and sum(1 for p in run.split("/") if _randomish(p)) >= 3 and _DIGIT_PLUS.search(run):
            spans.append(m.span())
    if not spans:
        return []
    spans.sort()
    n, floor, grown = len(text), 0, []
    for start, end in spans:
        if grown and end <= grown[-1][1] and start >= grown[-1][0]:
            continue                                  # inside what the last span already took
        while start > max(1, floor) and text[start - 1] == "/":
            j = start - 2
            while j >= floor and text[j] in _PIECE:
                j -= 1
            piece = text[j + 1:start - 1]
            if not piece or not _randomish(piece):
                break
            start = j + 1
        while end < n - 1 and text[end] == "/":
            k = end + 1
            while k < n and text[k] in _PIECE:
                k += 1
            e2 = k
            while e2 < n and e2 - k < 2 and text[e2] == "=":
                e2 += 1
            if k == end + 1 or not _randomish(text[end + 1:e2]):
                break
            end = e2
        if grown and start <= grown[-1][1]:
            grown[-1] = (grown[-1][0], max(grown[-1][1], end))
        else:
            grown.append((start, end))
        floor = grown[-1][1]
    return grown


def _rules_piece(piece, kind):
    if not piece or not _QUICK.search(piece):
        return piece
    piece = _ANY_USERINFO.sub(lambda m: _withheld("userinfo", len(m.group()), kind), piece)
    # the shared block's user-info rules, then every token rule on the same text: what any of them takes is withheld as one
    # run, so that no rule's order leaves a piece of what another would have taken
    piece = _outside(piece, _MARKER, lambda part: _BARE_USERINFO.sub(lambda m: _withheld("userinfo", len(m.group()), kind),
                                                                      _USERINFO.sub(lambda m: _withheld("userinfo", len(m.group()), kind), part)))
    return _outside(piece, _MARKER, lambda part: _spans_withheld(part, kind))


def _spans_withheld(part, kind):
    """Every span the shared block's token rules and the shapes added here find in `part`, joined where they touch or
    overlap, each withheld once."""
    spans = [(a, b, "token-shaped text") for a, b in _shared_spans(part)]
    spans += [m.span() + ("token-shaped text",) for m in _SLASHED_RANDOM.finditer(part) if _random_slashed(m.group())]
    spans += [m.span() + ("token-shaped text",) for m in _BASE64_KEY.finditer(part) if "/" in m.group() or "+" in m.group()]
    spans += [m.span() + ("token-shaped text",) for m in _TOKEN_HEAD.finditer(part)]
    spans += [m.span(1) + ("secret",) for m in _NAMED_SECRET.finditer(part)]
    spans += [m.span(1) + ("secret",) for m in _NAMED_FLAG.finditer(part)]
    spans += [m.span(1) + ("secret",) for m in _NAMED_SET.finditer(part)]
    spans += [m.span() + ("token-shaped text",) for m in _RUN_CAND.finditer(part) if _token_like(m.group(), False)]
    spans += [m.span() + ("long number",) for m in _LONG_DIGITS.finditer(part)]
    spans += [m.span() + ("private key",) for m in _PRIVATE_KEY.finditer(part)]
    if not spans:
        return part
    spans.sort()
    merged = []
    for a, b, what in spans:
        if merged and a <= merged[-1][1]:
            prev = merged[-1]
            merged[-1] = (prev[0], max(prev[1], b), prev[2] if prev[2] == what else "token-shaped text")
        else:
            merged.append((a, b, what))
    out, last = [], 0
    for a, b, what in merged:
        out.append(part[last:a])
        out.append(_withheld(what, b - a, kind))
        last = b
    out.append(part[last:])
    return "".join(out)


def _free_once(text, kind):
    """One application of the layer 2 rules to a whole string. A string with invisible characters is judged with them taken
    out; when that reading has something to withhold, it is the one shown."""
    flat = _flat(text)
    if flat is not text and flat != text:
        sealed = _free_once(flat, kind)
        if sealed != flat:
            return sealed
    if not _QUICK.search(text):
        return text
    hit = _outside(text, _GUID_ALONE, lambda piece: _rules_piece(piece, kind))
    if kind == "boundary":
        COUNTS.pop("boundary", None)
    return hit


# ---- layer 1: the allow-list ---------------------------------------------------------------------------------------------
_NAME_PLAIN = re.compile(r"[A-Za-z0-9 ._()+\[\]'#,&~%$-]*")
_PATH_PLAIN = re.compile(r"[A-Za-z0-9 ._()+\[\]'#,&~%{}$-]*")
_VERSION_PLAIN = re.compile(r"[A-Za-z0-9 ._()+\[\]'#,&~%/-]*")
_SEP_DIGITS = re.compile(r"(?<=[0-9])[:/](?=[0-9])")
_RUN_CAND = re.compile(r"[A-Za-z0-9_+=-]{16,}")
_SECRET_WORD = re.compile(r"(?i:passw|pwd|secret|token|credential|api[_-]?key|private[_-]?key|access[_-]?key)(?:ord|wd|phrase)?")
_ALNUM_RUN = re.compile(r"[A-Za-z0-9]+")
_PATH_RUN = re.compile(r"[A-Za-z0-9_+=/-]{18,}")
_DRIVE = re.compile(r"[A-Za-z0-9_.-]{1,40}")
# identifiers of a kind that stay readable inside a name or a path: a GUID (a Hyper-V file name holds one), the volume id of
# /vmfs/volumes/<id>/, the device ids naa. eui. wwn- vml., and the name Windows gives a machine that was not named (WIN-, DESKTOP-
# or LAPTOP- and capitals and digits: 15 characters, which a VM's disk, snapshot and configuration file names repeat).
_ID_EMBEDDED = re.compile(
    r"(?<![A-Za-z0-9])(?:WIN-[A-Z0-9]{11}|DESKTOP-[A-Z0-9]{7}|LAPTOP-[A-Z0-9]{8}|\{?[0-9A-Fa-f]{8}(?:-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}\}?|[0-9a-f]{8}-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{12}"
    r"|naa\.[0-9a-fA-F]{16,32}|eui\.[0-9a-fA-F]{16}|wwn-0x[0-9a-fA-F]{16}|vml\.[0-9a-fA-F]{20,40}"
    r"|iqn\.[0-9]{4}-[0-9]{2}\.[a-z0-9][a-z0-9.-]{0,60}(?::[A-Za-z0-9._-]{1,40})?"
    r"|t10\.[A-Za-z]{2,12}_[A-Za-z0-9 _.-]{1,50}_[A-Za-z0-9]{4,24})(?![A-Za-z0-9])")
# A run of underscores in a t10. id is read by the class beside it, never by two `_+` around it: that pair tried every split of the run
# (`t10.AB` and 4,000 underscores took 3 s). An iqn. or t10. form carries a name the evidence chose, so it is accepted as an id only
# when what it carries is a name and not a stretch of random text (_id_plausible); otherwise it is judged like any other text.
_ID_SEGMENT = re.compile(r"[^_ ]+")


def _id_plausible(text):
    """Whether an iqn. or t10. id holds names: an iqn. whose domain and target have no token-like run, a t10. whose vendor, model and
    serial pieces are short or do not mix capitals, small letters and digits as random text does. A GUID or a hexadecimal id is as it is."""
    if text.startswith("iqn."):
        return not any(_token_like(run) for run in _RUN_CAND.findall(text[12:]))
    if text.startswith("t10."):
        for piece in _ID_SEGMENT.findall(text[4:]):
            if len(piece) >= 16 and (len(piece) > 24 or (_HAS_LOWER.search(piece) and _HAS_UPPER.search(piece) and _HAS_DIGIT.search(piece) and _token_like(piece))):
                return False
    return True


def _id_sub(text, fill):
    """`text` with each id of a kind in it replaced by fill(id); an iqn. or t10. form that is not plausible stays as the text it is."""
    return _ID_EMBEDDED.sub(lambda m: fill(m.group()) if _id_plausible(m.group()) else m.group(), text)


def _id_is(text):
    return _ID_EMBEDDED.fullmatch(text) is not None and _id_plausible(text)


# the forms an identifier field may hold: a GUID, a VMFS volume id, VMware's uuid bytes, up to 16 hexadecimal digits (a CID), 32 (a
# content id), a number, a MAC or WWN, a device id, a counter (S000001), a short word (snapshot0, current, vm-100)
_ID_FORMS = re.compile(
    r"\{?[0-9A-Fa-f]{8}(?:-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}\}?|[0-9a-f]{8}-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{12}"
    r"|(?:[0-9A-Fa-f]{2} ){7}[0-9A-Fa-f]{2}-(?:[0-9A-Fa-f]{2} ){7}[0-9A-Fa-f]{2}|(?:[0-9A-Fa-f]{2} ){15}[0-9A-Fa-f]{2}"
    r"|[0-9A-Fa-f]{1,16}|[0-9A-Fa-f]{32}|[0-9]{1,18}|(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}|(?:[0-9A-Fa-f]{2}:){7}[0-9A-Fa-f]{2}"
    r"|naa\.[0-9a-fA-F]{16,32}|eui\.[0-9a-fA-F]{16}|wwn-0x[0-9a-fA-F]{16}|vml\.[0-9a-fA-F]{20,40}|mpx\.vmhba[0-9]+:C[0-9]+:T[0-9]+:L[0-9]+"
    r"|[A-Za-z][A-Za-z0-9_.-]{0,15}[0-9]{0,6}")
_DENY_IN_IDENT = re.compile(r"(?i:(?:AKIA|ASIA)[0-9A-Z]{4,}|gh[pousr]_[A-Za-z0-9]{4,}|github_pat_|xox[abeprs]-|glpat-|(?:sk|rk|pk)_(?:live|test)_|SG\.[A-Za-z0-9_-]{8,}"
                            r"|AIza|npm_|pypi-|shpat_|dop_v1_|ya29\.|sk-[A-Za-z0-9_-]{8,})|eyJ[A-Za-z0-9_-]{10,}|-----BEGIN|[A-Za-z0-9_-]{0,40}(?i:passw|pwd|secret|token|credential|api[_-]?key|private[_-]?key|access[_-]?key|account[_-]?key)[A-Za-z0-9_-]{0,3}[=:]"
                            r"|(?<![A-Za-z])(?i:pass|pw|auth|sig|sas)s?[=:]")
_VOWELS = frozenset("aeiouAEIOU")


def _cls(c):
    return 0 if c.isdigit() else 1 if c.isupper() else 2


def _token_like(run, hex_too=True, words=True):
    """Whether a run of letters and digits (joined across - _ + =) of 16 or more is a token and not words, a date, a version or a
    counter: hexadecimal, digits packed between letters, class changes (capital, small letter, digit) as random text has them,
    capitals in pairs, or letters with no word structure. Thresholds were set on a corpus of VM, host, datastore, snapshot and
    file names against random text of 14 to 40 characters (the measured rates are in the pack's changelog)."""
    if len(run) >= 16:
        run = _DATE.sub("-", run)                    # a date or a time stamp in a file name (Veeam's D2022-03-28T152355) is not a token
    alnum = "".join(c for c in run if c.isalnum())
    n = len(alnum)
    if n < 16:
        return False
    nd = sum(1 for c in alnum if c.isdigit())
    if nd == n:
        return n >= 19
    if all(c in "0123456789abcdefABCDEF" for c in alnum):
        return hex_too
    if hex_too and _HEX32.search(alnum):
        return True                                 # a digest or a key written in hexadecimal inside a longer name
    kinds = {_cls(c) for c in alnum}
    changes = sum(1 for a, b in zip(alnum, alnum[1:]) if _cls(a) != _cls(b)) / (n - 1)
    packed = len(_PACKED.findall(alnum))
    if kinds >= {1, 2} and sum(len(w) for w in _WORDS.findall(alnum)) >= 0.7 * n:
        return False                                # capitalised words written together (ProxyK8sMgmtNode10), not a token
    if words and n >= 28 and len(kinds) >= 2 and sum(len(w) for w in _WORDISH.findall(alnum)) < 0.6 * max(1, n - nd):
        return True                                 # a long run whose letters are not made of words (a counter's digits do not count)
    if len(kinds) == 3:
        if n < 18:
            return changes >= 0.5
        upper_pairs = sum(1 for a, b in zip(alnum, alnum[1:]) if a.isupper() and b.isupper()) / (n - 1)
        return changes >= 0.45 or (changes >= 0.30 and upper_pairs >= 0.08) or packed >= 4 or (n < 20 and changes >= 0.5)
    if n < 18:
        return kinds == {0, 1} and nd >= 3 and (changes >= 0.3 or packed >= 2)      # 16 or 17 capitals and digits (a base32 seed)
    if kinds == {1, 2}:
        upper_pairs = sum(1 for a, b in zip(alnum, alnum[1:]) if a.isupper() and b.isupper()) / (n - 1)
        return changes >= 0.45 or (changes >= 0.35 and upper_pairs >= 0.10)
    if len(kinds) == 2:
        return nd >= 3 and (changes >= 0.30 or packed >= 2)
    for piece in ([run] if run.isalnum() else re.split(r"[_+=-]+", run)):    # words joined by - or _ (esxi_vm_inventory_xml) are judged one by one
        piece = piece.lower()
        if len(piece) < (18 if piece is not run else 14):
            continue
        vowels = sum(1 for c in piece if c in _VOWELS)
        longest = cons = 0
        for c in piece:
            cons = 0 if c in _VOWELS else cons + 1
            longest = max(longest, cons)
        if vowels / len(piece) < 0.2 or longest >= 5:
            return True
    return False


_PACKED = re.compile(r"(?<=[A-Za-z])[0-9]{1,2}(?=[A-Za-z])")
_WORDS = re.compile(r"[A-Z][a-z]{2,}")
_HEX32 = re.compile(r"[0-9a-fA-F]{32,}")
_DATE = re.compile(r"(?:19|20)[0-9]{2}[-_.]?[0-1][0-9][-_.]?[0-3][0-9](?:[T_-]?[0-2][0-9][:.]?[0-5][0-9][:.]?[0-5][0-9])?(?![0-9])")
_WORDISH = re.compile(r"[A-Z]{2,4}(?=[A-Z][a-z]{3,})|[A-Z][a-z]{3,}|[a-z]{5,}")


def _piece_random(piece):
    """A piece of a path that looks like a stretch of a base64 key: 6 or more characters with a digit, a capital and a small letter,
    no word of four small letters, and class changes as random text has them."""
    if len(piece) < 6 or not ((_HAS_DIGIT.search(piece) and _HAS_UPPER.search(piece) and _HAS_LOWER.search(piece)) or ("+" in piece and _HAS_UPPER.search(piece) and _HAS_LOWER.search(piece))) or _WORD4.search(piece):
        return False
    alnum = [c for c in piece if c.isalnum()]
    return len(alnum) >= 5 and sum(1 for a, b in zip(alnum, alnum[1:]) if _cls(a) != _cls(b)) / (len(alnum) - 1) >= 0.5


_HAS_DIGIT, _HAS_UPPER, _HAS_LOWER, _WORD4 = re.compile(r"[0-9]"), re.compile(r"[A-Z]"), re.compile(r"[a-z]"), re.compile(r"[a-z]{4,}")


def _cross_slash_token(run):
    """A run of letters and digits that goes across `/` and is random as a whole: a base64 key cut by its slashes. A path of words and
    counters, or of capitals and digits only (SAN-LUN10/FILE8), is not one."""
    if "/" not in run or _HAS_UPPER.search(run) is None or _HAS_LOWER.search(run) is None:
        return False
    if sum(len(w) for w in _WORDISH.findall("".join(c for c in run if c.isalnum()))) >= 0.6 * max(1, sum(c.isalpha() for c in run)):
        return len(run) >= 36 and _random_run(run)
    return ((len(run) >= 30 and _HAS_DIGIT.search(run) is not None and _token_like(run.replace("/", ""), True, False)) or (len(run) >= 30 and _random_run(run))
            or (len(run) >= 20 and "+" in run))


def _ident_text_ok(text, limit, path, slash=False):
    """The grammar of a name or of one path component."""
    if len(text) > limit:
        return False
    if not text.isascii():
        n = unicodedata.normalize("NFKC", text)
        if any(unicodedata.category(c) in _STRIP_CATS or ord(c) in _FILLERS or not (c.isascii() or c.isalnum()) for c in n):
            return False
        text = "".join(c if c.isascii() else "a" for c in n)
    probe = _SEP_DIGITS.sub("", _id_sub(text, lambda _: "x")) if len(text) >= 12 else _SEP_DIGITS.sub("", text)
    if path and ":" in probe:
        head, _, tail = probe.partition(":")       # a drive (C:), a storage id (local-lvm:vm-100-disk-0), host:port
        if ":" in tail or not _DRIVE.fullmatch(head):
            return False
        probe = head + tail
    if not (_PATH_PLAIN if path else _VERSION_PLAIN if slash else _NAME_PLAIN).fullmatch(probe) or _DENY_IN_IDENT.search(_id_sub(text, lambda _: "x")):
        return False
    scan = _id_sub(text, lambda _: " ") if len(text) >= 15 else text
    for m in _RUN_CAND.finditer(scan):
        if _token_like(m.group()):
            return False
    if slash:
        for m in _PATH_RUN.finditer(scan):
            if _cross_slash_token(m.group()):
                return False
    if _SECRET_WORD.search(text):                  # the name of a secret in a name: no random-looking piece beside it (words are not)
        for piece in _ALNUM_RUN.findall(_SECRET_WORD.sub(" ", text)):
            if len(piece) >= 10 and len({_cls(c) for c in piece}) >= 2 and sum(len(w) for w in _WORDS.findall(piece)) < 0.7 * len(piece):
                return False
    return True


def _ident(text, kind, field, where):
    """A string of an identifier-shaped field: shown as it is when it fits the grammar of its type, else withheld by its size
    and field (a path component by component)."""
    orig = text
    if kind == "path" and not text.isascii():
        text = _SURROGATE_BYTE.sub(lambda m: "\\x%02x" % (ord(m.group()) - 0xDC00), text)       # a byte that was not UTF-8, as \xNN
    marker = _CUT_NOTE.search(text)
    body = text[:marker.start()] if marker else text
    if not body or body in OWN_NAMES or body in VOCABULARY or _MARKER.fullmatch(body):
        return text
    if _flat(body, False, False) != body:           # an invisible character, or the escape of one, is not part of a plain name
        _keep_original(orig, field, where)
        return "<withheld: %d bytes, field %s>" % (blen(orig), field if field_kind(field) else "name")
    if kind == "id":
        if (_ID_FORMS.fullmatch(body) or _id_is(body)) and not _DENY_IN_IDENT.search(body):        # the ids a name or a path shows (t10., iqn.) are shown in an id field too
            return text
        return _withhold_field(text, field, where)
    if kind == "path":
        parts = _SEP.split(body)
        ok = [i % 2 == 1 or not p or _MARKER.fullmatch(p) is not None or p in OWN_NAMES or _ident_text_ok(p, 255, True) for i, p in enumerate(parts)]
        # What each piece holds at the edge a key's neighbour would join: a piece of the key alphabet alone is all key; a piece with
        # something glued to it (`local:`, `[ds1] `, `C:`, a quote or a brace, an error message) holds a stretch of key at the end that
        # is not glued (its tail, for the piece left of a `/`, its head for the piece right of one). A withheld piece whose edge is
        # a stretch of key seeds the sweeps below like a withheld piece of the key alphabet alone.
        pure, heads, tails, seeds_r, seeds_l = set(), {}, {}, set(), set()
        for i in range(0, len(parts), 2):
            stem = parts[i].partition(".")[0]
            if _KEY_PIECE.fullmatch(stem):
                pure.add(i)
                heads[i] = tails[i] = stem
                if not ok[i]:                       # a piece withheld that a key's pieces are made of
                    seeds_r.add(i)
                    seeds_l.add(i)
            else:
                heads[i], tails[i] = _key_head(stem), _key_tail(parts[i])
                if not ok[i]:
                    if _key_edge(tails[i]):
                        seeds_r.add(i)
                    if _key_edge(heads[i]) or (len(heads[i]) >= 3 and heads[i].endswith("=") and heads[i].rstrip("=")):      # the padding of a key
                        seeds_l.add(i)
        run = []                                    # two pieces in a row that look like stretches of a base64 key: the key was cut by its `/`
        for i in range(0, len(parts), 2):
            if ok[i] and _piece_random(_id_sub(parts[i], lambda _: "")):          # a GUID, a volume id or a default machine name in a piece is not a stretch of a key
                run.append(i)
                continue
            if len(run) >= 2:
                for j in run:
                    ok[j] = False
                    seeds_r.add(j)
                    seeds_l.add(j)
            run = []
        if len(run) >= 2:
            for j in run:
                ok[j] = False
                seeds_r.add(j)
                seeds_l.add(j)
        scan = _id_sub(body, lambda found: " " * len(found))
        i0 = pos0 = 0                                    # the first piece that can overlap the next run (runs come in order: each piece is passed once)
        for m in _PATH_RUN.finditer(scan):               # a run of letters and digits that goes across `/` is judged as one: a base64 key cut by its slashes
            while i0 < len(parts) and pos0 + len(parts[i0]) <= m.start():
                pos0 += len(parts[i0])
                i0 += 1
            if _cross_slash_token(m.group()):
                pos, hit = pos0, []
                for i in range(i0, len(parts)):
                    if pos >= m.end():
                        break
                    if i % 2 == 0 and parts[i]:
                        hit.append((i, body[max(pos, m.start()):min(pos + len(parts[i]), m.end())]))      # the piece, and the part of it the run covers
                    pos += len(parts[i])
                while len(hit) > 1 and not _randomish(hit[0][1]):       # the plain words either side of the key (vmfs, volumes, a datastore) stay readable
                    hit.pop(0)
                while len(hit) > 1 and not _randomish(hit[-1][1]):
                    hit.pop()
                for i, _ in hit:
                    ok[i] = False
                    seeds_r.add(i)
                    seeds_l.add(i)
        # A key cut by its `/` is withheld in every piece: from a withheld piece whose edge is key, the pieces next to it across a
        # `/` (an empty one for `//`, a short one only if a random-looking one follows it) are withheld as far as the last random-looking
        # one; a piece with something glued to it ends the key, and is withheld when the edge toward the key is a random-looking stretch.
        # One sweep to the right and one to the left, each piece read twice at most.
        for step in (2, -2):
            seeds = seeds_r if step == 2 else seeds_l
            active, pending = False, []
            for k in (range(0, len(parts), 2) if step == 2 else range(len(parts) - 1, -1, -2)):
                before = k - 1 if step == 2 else k + 1
                if not 0 <= before < len(parts) or parts[before] != "/":
                    active, pending = False, []
                stem = parts[k].partition(".")[0]
                if k in seeds:
                    take, active, pending = pending, True, []
                elif not active:
                    continue
                elif not parts[k]:
                    pending.append(k)                   # `//` inside a key: an empty piece
                    continue
                elif not ok[k]:
                    take, pending = pending, []
                elif k not in pure or _id_is(parts[k]):
                    edge = heads[k] if step == 2 else tails[k]
                    take = pending + [k] if k not in pure and _key_edge(edge, 4) else []
                    active, pending = False, []
                elif _randomish(stem):
                    take, pending = pending + [k], []
                elif len(stem) <= 8:
                    pending.append(k)                   # a short piece belongs to the key only if a random-looking one follows it
                    continue
                else:
                    active, pending = False, []
                    continue
                for j in take:
                    ok[j] = ok[j] and not parts[j]
        for i in range(2, len(parts) - 2, 2):       # one random-looking piece between two that are withheld is the middle of the key
            if ok[i] and i in pure and parts[i - 1] == "/" == parts[i + 1] and not ok[i - 2] and not ok[i + 2] and len(heads[i]) >= 8 and _randomish(heads[i]) and not _id_is(parts[i]):
                ok[i] = False
        if all(ok):
            return text
        _keep_original(orig, field, where)
        out = [p if ok[i] else "<withheld: %d bytes, field %s>" % (blen(p), field if field_kind(field) else "path") for i, p in enumerate(parts)]
        return "".join(out) + (marker.group() if marker else "")
    if _ident_text_ok(body, 160 if kind in ("name", "key") else 96, False, slash=(kind == "simple")):
        return text
    return _withhold_field(text, field, where)


_SEP = re.compile(r"([/\\])")
_KEY_PIECE = re.compile(r"[A-Za-z0-9+=_-]+")
_KEY_SET = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+=_-")


def _key_edge(edge, least=8):
    """The end of a piece that has something glued to it, next to a `/`: `least` or more characters of the key alphabet that mix capitals,
    small letters and digits or capitals inside a word as a stretch of a key does (a time stamp, `vm-100-disk-0` and a plain word do not)."""
    return len(edge) >= least and _randomish(edge) and _HAS_UPPER.search(edge) is not None and _HAS_LOWER.search(edge) is not None


def _key_head(text):
    """The longest start of `text` made of the key alphabet [A-Za-z0-9+=_-] (a scan, not a pattern: linear whatever follows)."""
    n = 0
    while n < len(text) and text[n] in _KEY_SET:
        n += 1
    return text[:n]


def _key_tail(text):
    """The longest end of `text` made of the key alphabet."""
    n = len(text)
    while n > 0 and text[n - 1] in _KEY_SET:
        n -= 1
    return text[n:]
_SURROGATE_BYTE = re.compile("[\udc80-\udcff]")


def _keep_original(text, field, where):
    COUNTS["identifiers"] = COUNTS.get("identifiers", 0) + 1
    values = RUN["values"]
    if RUN["record"] and values is not None and values.enabled:
        values.add({"record_type": "original", "where": where or None, "field": field, "value": text})


def _withhold_field(text, field, where):
    _keep_original(text, field, where)
    return "<withheld: %d bytes, field %s>" % (blen(text), field if field_kind(field) else "name")


# ---- the judgement of one string ------------------------------------------------------------------------------------------

def _out_of_budget(text):
    """True when this string was not judged before and the run's time or character budget is spent: it is withheld by its size."""
    RUN["chars"] += len(text)
    stop = RUN["stop"]
    if stop is None:
        if RUN["chars"] > RUN["cap"]:
            RUN["stop"] = stop = "the cap of %d characters judged in one run" % RUN["cap"]
        elif RUN["deadline"] is not None and time.monotonic() > RUN["deadline"]:
            RUN["stop"] = stop = "max_seconds"
    return stop is not None


def seal_text(text, kind="boundary", field=None, where=""):
    """The rules for the type of `field` applied to a whole string: layer 1 for an identifier-shaped field, else layer 2 until it
    changes nothing (a string that keeps changing is withheld whole), so that the check after it finds nothing to change.
    The Shower uses this too, so that what it shows and what the way out lets through are judged by the same rules."""
    if not isinstance(text, str):
        text = str(text)
    fk = field_kind(field) if field else None
    if field == "key":
        fk = "key"
    key = (fk, text) if len(text) <= 512 else None
    hit = _SEALED.get(key) if key else None
    if hit is not None:
        return hit
    if text in OWN_NAMES or text in VOCABULARY:
        return text
    if _out_of_budget(text):
        RUN["stopped_strings"] += 1
        return "<withheld: %d bytes, run limit>" % blen(text)
    rest = ""
    if len(text) > MAX_ONE_STRING:
        rest, text = _withheld("rest of a long text", len(text) - MAX_ONE_STRING, kind), text[:MAX_ONE_STRING]
    if fk in _IDENT_KINDS:
        hit = _ident(text, fk, field, where)
    else:
        hit = text
        for _ in range(6):
            before, hit = hit, _free_once(hit, kind)
            if hit == before:
                break
        else:
            hit = "<withheld: %d bytes>" % blen(text)
    hit += rest
    if key:
        if len(_SEALED) >= 30000:
            _SEALED.clear()
        _SEALED[key] = hit
    return hit


def seal_head(text, kind="boundary", field=None, where=""):
    """seal_text for a call site that reads a piece of a string the evidence supplied (a name, a path, a message) and is not
    the Shower: at most the first Shower.EXAMINED characters are judged (the cut leaves no open run), and a longer text is
    shown with its whole length, as the Shower shows it. A text that long is never an identifier, so nothing legitimate is lost."""
    if not isinstance(text, str):
        text = str(text)
    if len(text) <= Shower.EXAMINED:
        return seal_text(text, kind, field, where)
    return seal_text(cut_safely(text, Shower.EXAMINED), kind, field, where) + "...(whole text: %d characters)" % len(text)


def boundary_text(text, field=None, where=""):
    """The seal of one string at the way out, counted when it changed something. A string the Shower judged is not judged again."""
    if getattr(text, "judged", False):
        return text
    hit = seal_text(text, "boundary", field, where)
    if hit != text:
        BOUNDARY["withheld"] += 1
    return hit


def big_int(value):
    """An integer of more than 18 digits: no format this pack reads carries one, and its digits can be a secret's."""
    return isinstance(value, int) and not isinstance(value, bool) and abs(value) >= 10 ** 18


def seal(value, depth=0, field=None, where=""):
    """Every key and every value of a structure, as JSON will write it, through boundary_text; a key two keys seal to is
    numbered (`<key> #2`), never merged. `field` is the key the value sits under (a list's items sit under its key)."""
    if isinstance(value, str):
        return boundary_text(value, field, where)
    if big_int(value):
        BOUNDARY["withheld"] += 1
        return "<withheld: an integer of %d bits>" % value.bit_length()
    if value is None or isinstance(value, (bool, int)):
        return value
    if isinstance(value, float):
        return value if math.isfinite(value) else boundary_text(repr(value))
    if depth > 64:
        return boundary_text(json.dumps(value, default=str))
    if isinstance(value, dict):
        out, taken = {}, {}
        for k, v in value.items():
            raw = k if isinstance(k, str) else json.dumps(k) if isinstance(k, (bool, type(None))) else str(k)
            key = raw if raw in _FIELDS and raw != "key" else boundary_text(raw, "key", where + "/(key)")
            if key in out:
                n = taken.get(key, 1) + 1
                while "%s #%d" % (key, n) in out:
                    n += 1
                taken[key] = n
                key = "%s #%d" % (key, n)
            out[key] = seal(v, depth + 1, field if raw in _INHERIT else raw, where + "/" + key)
        return out
    if isinstance(value, (list, tuple, set, frozenset)):
        return [seal(v, depth + 1, field, "%s/%d" % (where, i)) for i, v in enumerate(value)]
    return boundary_text(str(value), field, where)


# ---- layer 3: the backstop, written apart from the layers above -----------------------------------------------------------
# Its own normaliser: every character of a C category, a mark that combines or encloses, a line or paragraph separator, a blank
# filler; and the escapes \uXXXX \UXXXXXXXX \xNN of such a character.
_S_ESC = re.compile(r"(?<!\\)\\+(?:u([0-9a-fA-F]{4})|U([0-9a-fA-F]{8})|u\{([0-9a-fA-F]{1,6})\}|x([0-9a-fA-F]{2}))")
_S_FILL = "\u115f\u1160\u3164\uffa0\u2800"


def _s_gone(c):
    cat = unicodedata.category(c)
    return cat[0] == "C" or cat in ("Mn", "Me", "Zl", "Zp") or c in _S_FILL


def _s_unesc(m):
    try:
        c = chr(int(m.group(1) or m.group(2) or m.group(3) or m.group(4), 16))
    except (ValueError, OverflowError):
        return m.group(0)
    return "" if _s_gone(c) else m.group(0)


def _s_normal(text):
    if "\\" in text:
        text = _S_ESC.sub(_s_unesc, text)
    if text.isascii() and text.isprintable():
        return text
    kept = [c for c in text if not _s_gone(c)]
    return unicodedata.normalize("NFKC", "".join(kept))


_S_PEM = re.compile(r"-----BEGIN [A-Z0-9 ]{0,40}PRIVATE KEY|PRIVATE KEY-----")
# A secret's name, read from the delimiter back: the name is the run of name characters before an `=` or a `:`
_S_DELIM = re.compile(r"[=:]")
_S_LINE = re.compile(r"[ \t]*line[ \t]+[0-9]")
_S_NAME_CHARS = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_.-")
_S_STRONG = ("password", "passwd", "passphrase", "passw", "pwd", "secret", "token", "credential", "apikey", "api_key", "api-key", "accesskey", "access_key", "access-key",
             "accountkey", "account_key", "account-key", "privatekey", "private_key", "private-key", "masterkey", "master_key", "sharedkey", "shared_key", "signingkey", "encryptionkey",
             "secretkey", "secret_key", "secret-key", "pass_word", "pass-word", "authorization", "bearer", "psk", "otp", "dsn", "webhook_url", "webhookurl", "webhook-url",
             "connection_string", "connectionstring", "connection-string", "ssh_key", "sshkey", "ssh-key", "snmp_community", "snmpcommunity", "community_string")
_S_WEAK = ("pass", "pw", "auth", "sig", "sas", "pin")
_S_NOT_PASS = ("bypass", "compass", "overpass", "underpass", "trespass", "encompass", "surpass", "impass")
_S_WORDS = re.compile(r"[A-Z]+(?![a-z])|[A-Z]?[a-z]+|[0-9]+")
_S_DIGITS = re.compile(r"[0-9]{19}")
_S_HEXRUN = re.compile(r"(?<![0-9A-Za-z])[0-9A-Fa-f]{40,}(?![0-9A-Za-z])")
_S_B64NOPAD = re.compile(r"[A-Za-z0-9+/]{20,}")
_S_B64PAD = re.compile(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{15,}={1,2}(?![A-Za-z0-9+=])")
_S_PREFIX = re.compile(r"(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA|ANVA|AIPA)[A-Z0-9]{12}|(?:gh[pousr]_|github_pat_|glpat-|xox[a-z]-|xapp-|sk-|sk_live_|rk_live_|pk_live_|sk_test_"
                       r"|npm_|pypi-|shpat_|dop_v1_|AIza|ya29\.|SG\.)[A-Za-z0-9_-]{12}|eyJ[A-Za-z0-9_-]{12}")
_S_USERINFO = re.compile(r"[^\s/@:<>\"']{1,64}:[^\s/<>\"']{1,128}@[^\s/@<>\"']")
_S_RUN = re.compile(r"[A-Za-z0-9+/_-]{20,}")
_S_HEX = re.compile(r"[0-9A-Fa-f-]+")
_S_IDS = re.compile(r"[0-9A-Fa-f]{8}-(?:[0-9A-Fa-f]{4}-){3}[0-9A-Fa-f]{12}|[0-9A-Fa-f]{8}-[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}|(?:naa|eui|wwn-0x|vml)\.?[0-9A-Fa-f]{16,40}|t10\.[A-Za-z0-9_.]{8,120}"
                    r"|iqn\.[0-9]{4}-[0-9]{2}\.[a-z0-9][a-z0-9.-]{0,60}(?::[A-Za-z0-9._-]{1,40})?")
_S_MARK = re.compile(r"<[^<>]{0,80}withheld[^<>]{0,100}>")
# a value in angle brackets is a value; only the empty brackets (what a marker leaves) and a placeholder word are not
_S_PH = r"<(?:redacted|hidden|masked|removed|omitted|secret|password|passwd|passphrase|pwd|pass|token|key|value|placeholder|empty|none|null|unset|your[ _-]?(?:password|secret|token|key)|\*{1,16})?>"
_S_FLAG = re.compile(r"(?<![\w-])(?:--?(?:pass|password|passwd|passphrase|pwd|secret|token|apikey|api-key|api_key|access[-_]?key|client[-_]secret|auth|bearer|psk)|(?:set|enable)[ \t]+(?:password|secret|passphrase|token))[= ](?!" + _S_PH + r")\S", re.I)
_S_PHM = re.compile(_S_PH, re.I)


def _class(c):
    return 0 if c.isdigit() else 1 if c.isupper() else 2


def _random_run(run):
    """A run that changes between capitals, small letters and digits as random text does (an English name, a path, a
    version or a hexadecimal identifier does not)."""
    if _S_HEX.fullmatch(run):
        return False
    pieces = [p for p in re.split(r"[/_+-]", run) if p]
    alnum = "".join(pieces)
    if len(alnum) < 20 or max(len(p) for p in pieces) < 12:
        return False
    kinds = {_class(c) for c in alnum}
    if len(kinds) < 2:
        return False
    lower = [len(r) for r in re.findall(r"[a-z]+", alnum)]
    if lower and sum(lower) >= 3 * len(lower) and not re.search(r"[A-Z]{2}", alnum):
        return False                        # words written together (WebServerPrimary01): capitals one at a time, words of three letters or more
    changes = sum(1 for a, b in zip(alnum, alnum[1:]) if _class(a) != _class(b)) / (len(alnum) - 1)
    digit_runs = len(re.findall(r"[0-9]+", alnum))
    if kinds == {0, 1, 2}:
        return changes >= 0.42 or (changes >= 0.3 and digit_runs >= 4 and len(set(alnum)) >= 0.6 * len(alnum))
    if kinds == {1, 2}:                    # letters only: only a case pattern no word has
        return changes >= 0.5 and len(alnum) >= 24
    return changes >= 0.4 and digit_runs >= 5 and len(set(alnum)) >= 0.5 * len(alnum)     # one case of letters and digits


def _s_named(flat):
    """A secret's name right before an `=` or a `:` that has something after it: the name is the run of name characters that ends
    at the delimiter (read from the delimiter back, not from the secret word forward)."""
    pos = 0
    while True:
        m = _S_DELIM.search(flat, pos)
        if not m:
            return False
        i = m.start()
        pos = m.end()
        raw = flat[i + 1:i + 6]
        after = raw.lstrip(" \t\"'\\")
        if not after or after[0] == ">" or _S_LINE.match(flat, i + 1) or (after[0] == "<" and _S_PHM.match(flat, i + 1 + len(raw) - len(after))):
            continue                                  # nothing after it, a placeholder or what a marker leaves, or an error message's `: line 3, column 5`
        j = i
        while j > 0 and flat[j - 1] in " \t\"'\\" and i - j < 5:
            j -= 1
        k = j
        while k > 0 and j - k < 64 and flat[k - 1] in _S_NAME_CHARS:
            k -= 1
        name = flat[k:j]
        low = name.lower()
        for plural in ("", "s"):
            for word in (low, low.rstrip("0123456789")):          # password1, pass2
                if word.endswith(tuple(w + plural for w in _S_STRONG)):
                    return True
                if word.endswith(tuple(w + plural for w in _S_WEAK)) and not word.endswith(tuple(w + plural for w in _S_NOT_PASS)):
                    return True


def _suspect(text):
    """The name of the check a string fails, or None."""
    if text in OWN_NAMES or text in VOCABULARY or not text:
        return None
    if len(text) > MAX_ONE_STRING:
        text = text[:MAX_ONE_STRING]
    flat = _s_normal(text)
    if _S_MARK.search(flat):
        flat = _S_MARK.sub("<>", flat)
    if _S_PEM.search(flat):
        return "a PEM marker"
    bare = _S_IDS.sub(" ", flat)
    if _s_named(bare) or _S_FLAG.search(flat):
        return "a named secret"
    if _S_DIGITS.search(bare):
        return "a long digit run"
    if _S_PREFIX.search(flat):
        return "a token prefix"
    if _S_USERINFO.search(flat):
        return "user-info"
    if _S_HEXRUN.search(bare):
        return "a long hexadecimal run"
    for m in _S_B64NOPAD.finditer(bare):
        if "/" in m.group() and "+" in m.group() and len({_class(c) for c in m.group() if c.isalnum()}) == 3:
            return "a base64 run with / and +"
    for m in _S_B64PAD.finditer(bare):
        body = m.group().rstrip("=")
        if len({_class(c) for c in body}) >= 2 and (("/" in body or "+" in body) or len(body) >= 20):
            return "a padded base64 run"
    for m in _S_RUN.finditer(bare):
        if _random_run(m.group()):
            return "a random-looking run"
    return None


def _replace(value, where, check):
    BOUNDARY["replaced"] += 1
    BOUNDARY["by"][check] += 1
    if len(BOUNDARY["where"]) < MAX_REPLACED_LISTED:
        BOUNDARY["where"].append({"at": where or "/", "check": check})
    else:
        BOUNDARY["not_listed"] += 1
    return "<withheld: %d bytes>" % blen(value)


_CHECKED = {}


def _verdict(text):
    """None when the string passes the check, else the check it fails; remembered per string (keys and values repeat across rows)."""
    hit = _CHECKED.get(text, False)
    if hit is False:
        if _MARKER.fullmatch(text):
            return None
        if _out_of_budget(text):
            RUN["stopped_strings"] += 1
            return "run limit"
        check = _suspect(text)
        hit = "second check: %s" % check if check else None
        if len(text) <= 512:
            if len(_CHECKED) >= 30000:
                _CHECKED.clear()
            _CHECKED[text] = hit
    return hit


def backstop(value, where=""):
    """The serialised answer read back and checked: a string it finds suspect (a key or a value) is replaced by
    <withheld: N bytes>, counted, and its place named."""
    if isinstance(value, str):
        check = _verdict(value)
        return _replace(value, where, check) if check else value
    if big_int(value):
        return _replace(str(value), where, "second check: a long digit run")
    if isinstance(value, dict):
        out = {}
        for k, v in value.items():
            key = backstop(k, where + "/(key)")
            while key in out:
                key += " #"
            out[key] = backstop(v, where + "/" + key)
        return out
    if isinstance(value, list):
        return [backstop(v, "%s/%d" % (where, i)) for i, v in enumerate(value)]
    return value


def row_text(row, where):
    """One row of a paging file: sealed, serialised, read back and checked."""
    text = json.dumps(seal(row))
    before = BOUNDARY["replaced"]
    checked = backstop(json.loads(text), where)
    return text if BOUNDARY["replaced"] == before else json.dumps(checked)


def answer_text(doc):
    """The answer (or an error answer): sealed, serialised, read back and checked; a string the check had to replace, or a
    string withheld because the run's time or character budget was spent, makes a complete answer partial, and the answer says so."""
    if RUN["deadline"] is not None:
        RUN["deadline"] = max(RUN["deadline"], time.monotonic()) + 1.5      # a short grace for the final answer
    RUN["cap"] += 4000000
    stop = RUN["stop"]
    if stop is not None:
        RUN["stop"] = None
    text = json.dumps(seal(doc), indent=2)
    checked = backstop(json.loads(text), "")
    stop = RUN["stop"] or stop
    checked["boundary"] = {"strings_withheld_at_the_way_out": BOUNDARY["withheld"], "strings_replaced_by_the_check": BOUNDARY["replaced"],
                           "replaced_by_check": dict(BOUNDARY["by"]), "replaced_at": list(BOUNDARY["where"]), "replaced_not_listed": BOUNDARY["not_listed"],
                           "stopped_by": stop, "strings_withheld_by_the_stop": RUN["stopped_strings"],
                           "note": "every key and value of this answer and of its paging files was judged by the type of its field (a name, a path or an identifier is shown only "
                                   "when it fits a plain grammar, else it is <withheld: N bytes, field F>; any other text has token-shaped runs, user-info and the value after "
                                   "a secret's name withheld), then read back and checked by a second check written apart from them; a string the check replaced is "
                                   "<withheld: N bytes> and its place is in replaced_at (the first %d)" % MAX_REPLACED_LISTED}
    if (BOUNDARY["replaced"] or stop) and checked.get("status") == "complete":
        checked["status"] = "partial"
        why = []
        if BOUNDARY["replaced"]:
            why.append("%d string(s) still held a token-shaped text when the answer was checked on its way out and were replaced by <withheld: N bytes>" % BOUNDARY["replaced"])
        if stop:
            why.append("judging the strings stopped at %s: %d string(s) after it are withheld by their size" % (stop, RUN["stopped_strings"]))
        checked["status_basis"] = "%s; %s (see boundary)" % (checked.get("status_basis") or "", "; ".join(why))
    return json.dumps(checked, indent=2)
# END SHARED BOUNDARY
# BEGIN SHARED FILES
# The same text is in virtualization_inventory and snapshot_chain_check; tests/pack-virtualization-shared.test.ts holds the
# copies equal. The evidence is a set of files: a directory walked without following a link, and/or files named one by one.
# Nothing outside that set is ever opened, whatever a file inside it names.


def open_regular(path):
    """Open a regular file for reading without following a final link and without blocking on a pipe; None and the
    reason when it is not one."""
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_CLOEXEC", 0))
    except OSError as exc:
        return None, describe(exc)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            os.close(fd)
            return None, "not a regular file"
    except OSError as exc:
        os.close(fd)
        return None, describe(exc)
    return os.fdopen(fd, "rb"), None


class FileSet:
    """The files an examination covers, in a fixed order (names sorted), each with an id that is a sequence number and
    derived from nothing. What was not reached is counted and named: a link, a special file, a directory too deep, a
    listing that was cut at a cap."""

    def __init__(self, shower):
        self.files = []
        self.by_rel = {}
        self.shower = shower
        self.skipped = {"links": [], "special": [], "unreadable": [], "too_deep": []}
        self.skipped_counts = {"links": 0, "special": 0, "unreadable": 0, "too_deep": 0}
        self.lock_dirs = []
        self.lock_dirs_total = 0
        self.entries_seen = 0
        self.truncated = None
        self.root_shown = None

    def note(self, which, rel):
        self.skipped_counts[which] += 1
        if len(self.skipped[which]) < 200:
            self.skipped[which].append(self.shower(rel, "walk", which))

    def add_file(self, rel, path, size):
        if len(self.files) >= self.max_files:
            self.truncated = self.truncated or "max_files (%d) was reached: the files after the last one listed were not examined" % self.max_files
            return False
        fid = "S%06d" % (len(self.files) + 1)
        rec = {"id": fid, "rel": rel, "path": path, "size": size}
        self.files.append(rec)
        self.by_rel[rel] = rec
        return True

    def walk(self, root, paths, max_files, max_entries, max_depth, clock):
        self.max_files = max_files
        if root is not None:
            if os.path.islink(root):
                fail("refusing a symlink root: pass the evidence directory itself", root=root)
            if not os.path.isdir(root):
                fail("root is not a directory", root=root)
            self.root_shown = self.shower(root, "root", "root")
            stack = [("", 0)]
            while stack:
                rel_dir, depth = stack.pop()
                clock.check()
                here = os.path.join(root, rel_dir) if rel_dir else root
                try:
                    with os.scandir(here) as it:
                        entries = list(itertools.islice(it, max_entries - self.entries_seen + 1))
                except OSError as exc:
                    self.note("unreadable", (rel_dir or ".") + ": " + describe(exc))
                    continue
                if self.entries_seen + len(entries) > max_entries:
                    entries = entries[:max(0, max_entries - self.entries_seen)]
                    self.truncated = self.truncated or "max_entries (%d) was reached: the directories after the last one listed were not read" % max_entries
                    stack = []
                self.entries_seen += len(entries)
                entries.sort(key=lambda e: e.name)
                subdirs = []
                for e in entries:
                    clock.check(256)
                    rel = (rel_dir + "/" + e.name) if rel_dir else e.name
                    try:
                        if e.is_symlink():
                            self.note("links", rel)
                        elif e.is_dir(follow_symlinks=False):
                            if e.name.lower().endswith(".lck") or e.name.lower().startswith(".lck-"):
                                self.lock_dirs_total += 1
                                if len(self.lock_dirs) < 1000:
                                    self.lock_dirs.append(rel)
                            if depth + 1 > max_depth:
                                self.note("too_deep", rel)
                            else:
                                subdirs.append((rel, depth + 1))
                        elif e.is_file(follow_symlinks=False):
                            self.add_file(rel, os.path.join(root, rel), e.stat(follow_symlinks=False).st_size)
                        else:
                            self.note("special", rel)
                    except OSError as exc:
                        self.note("unreadable", rel + ": " + describe(exc))
                for item in reversed(subdirs):
                    stack.append(item)
                if self.truncated and "max_entries" in self.truncated:
                    break
        for p in paths:
            clock.check()
            try:
                st = os.lstat(p)
            except OSError as exc:
                self.note("unreadable", p + ": " + describe(exc))
                continue
            if stat.S_ISLNK(st.st_mode):
                self.note("links", p)
            elif not stat.S_ISREG(st.st_mode):
                self.note("special", p)
            else:
                rel = p
                if rel not in self.by_rel:
                    self.add_file(rel, p, st.st_size)

    def skipped_summary(self):
        return {"counts": dict(self.skipped_counts), "named": self.skipped,
                "note": "A link is listed and never followed; a special file is never opened; at most 200 of each are named, all are counted."}
class Index:
    def __init__(self, files):
        self.exact = {f["rel"]: f for f in files}
        self.fold = collections.defaultdict(list)
        self.base = collections.defaultdict(list)
        for f in files:
            self.fold[f["rel"].casefold()].append(f)
            self.base[posixpath.basename(f["rel"]).casefold()].append(f)

    def resolve(self, from_rel, hint):
        """(file or None, how). The hint is a string some file wrote; it is looked up among the files given and never opened."""
        if not hint or "\x00" in hint:
            return None, "no_name"
        h = hint.replace("\\", "/") if ("\\" in hint and "/" not in hint) else hint
        drive = bool(re.match(r"^[A-Za-z]:", h)) or h.startswith("/") or h.startswith("//") or h.startswith("vmfs/") or h.startswith("[")
        joined = None
        if not drive:
            joined = posixpath.normpath(posixpath.join(posixpath.dirname(from_rel), h))
            if joined.startswith("../") or joined == "..":
                joined = None
        if joined is not None:
            f = self.exact.get(joined)
            if f:
                return f, "relative_exact"
            hits = self.fold.get(joined.casefold(), [])
            if len(hits) == 1:
                return hits[0], "relative_case_insensitive"
        hits = self.base.get(posixpath.basename(h.rstrip("/")).casefold(), [])
        if len(hits) == 1:
            return hits[0], "basename_only"
        if len(hits) > 1:
            return None, "ambiguous_basename"
        return None, "not_in_set"


EXTENSION = re.compile(r"\.[A-Za-z0-9]{1,10}")


def ext_of(rel):
    """The extension a file is counted under: a short one of letters and digits as it is (lower case), none as (none),
    and any other under one bucket that shows nothing of it (a file name can carry a token after its last dot)."""
    ext = posixpath.splitext(posixpath.basename(rel))[1]
    if not ext:
        return "(none)"
    return ext.lower() if EXTENSION.fullmatch(ext) else "(other extensions)"
# END SHARED FILES
# BEGIN SHARED PROCESS
# The same text is in pcap_extract, zeek_run, suricata_run and the network-capture recipe; tests/pack-network-process.test.ts
# holds the copies equal. A program an engine tool runs is started in THIS tool's process group, never in a session of
# its own: the harness ends a tool that runs too long, or is aborted, by killing the tool's group (process.kill(-pid,
# SIGKILL)), and an engine in a group of its own goes on writing into the output directory after the tool is gone. On
# Linux the kernel is also asked to kill it if the tool dies. A deadline kills the program and what it started by
# walking the process tree, and SIGTERM, SIGINT and SIGHUP do the same and then give the tool a last word.
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


def descendants(pid):
    """Every process below `pid`, from /proc where there is one, else from ps."""
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
            out = subprocess.run(["ps", "-A", "-o", "pid=,ppid="], capture_output=True, text=True, timeout=10).stdout
            for line in out.splitlines():
                parts = line.split()
                if len(parts) == 2 and parts[0].isdigit() and parts[1].isdigit():
                    kids.setdefault(int(parts[1]), []).append(int(parts[0]))
    except (OSError, subprocess.SubprocessError):
        return []
    found, stack = [], [pid]
    while stack:
        for child in kids.get(stack.pop(), []):
            found.append(child)
            stack.append(child)
    return found


def kill_tree(proc):
    """Kill the program and everything it started. The children are listed first: once the parent is gone they are
    adopted by init and can no longer be found below it."""
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


# A value that is a number, a UUID or a run of hex bytes is shown as it is.
SAFE_VALUE = re.compile(r"[0-9]{1,12}|[0-9A-Fa-f]{8}(?:-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}|(?:[0-9A-Fa-f]{2}[ -]){3,31}[0-9A-Fa-f]{2}")


def make_net(shown, fid):
    """The net under every record: a string from the evidence that no call site has checked is checked here."""
    def net(value, depth=0, key="value"):
        if isinstance(value, str):
            if isinstance(value, Shown) or value in CREATE_TYPES or SAFE_VALUE.fullmatch(value):
                return value
            return shown(value, fid, key)
        if depth > 5:
            return value
        if isinstance(value, dict):
            return {k: net(v, depth + 1, k) for k, v in value.items()}
        if isinstance(value, list):
            return [net(v, depth + 1, key) for v in value]
        return value
    return net


# ---- small readers -----------------------------------------------------------------------------------------------

def read_at(fh, offset, length):
    if offset < 0 or length < 0:
        return b""
    fh.seek(offset)
    return fh.read(length)


def iso_utc(epoch, base=0):
    try:
        stamp = datetime.datetime(1970, 1, 1, tzinfo=datetime.timezone.utc) + datetime.timedelta(seconds=epoch + base)
        return stamp.strftime("%Y-%m-%dT%H:%M:%SZ")
    except (OverflowError, ValueError):
        return None


def guid_text(raw):
    return str(uuid.UUID(bytes_le=raw)).upper()


_CRC = []
for _i in range(256):
    _c = _i
    for _ in range(8):
        _c = (_c >> 1) ^ 0x82F63B78 if _c & 1 else _c >> 1
    _CRC.append(_c)


def crc32c(data):
    crc = 0xFFFFFFFF
    for b in data:
        crc = _CRC[(crc ^ b) & 0xFF] ^ (crc >> 8)
    return crc ^ 0xFFFFFFFF


# ---- VMDK ------------------------------------------------------------------------------------------------------------

EXTENT = re.compile(r'^(RW|RDONLY|NOACCESS)\s+(\d+)\s+([A-Za-z0-9_]+)(?:\s+"((?:[^"\\]|\\.)*)")?(?:\s+(\d+))?\s*(?:#.*)?$')
DESC_KV = re.compile(r'^([A-Za-z][A-Za-z0-9_.]*)\s*=\s*(.*)$')
CID_HEX = re.compile(r"^[0-9a-fA-F]{1,8}$")      # a 32-bit value in hexadecimal; qemu-img writes it without leading zeros
KNOWN_EXTENT_TYPES = {"FLAT", "SPARSE", "ZERO", "VMFS", "VMFSSPARSE", "VMFSRDM", "VMFSRAW", "VMFSPASSTHRU", "SESPARSE"}
NOT_A_FILE_EXTENT = ("ZERO", "VMFSRDM", "VMFSRAW", "VMFSPASSTHRU")


def cid_value(text):
    """A CID as eight lowercase hexadecimal digits, compared as the number it is; None when it is not one."""
    return "%08x" % int(text, 16) if text and CID_HEX.match(text) else None


def unquote(value):
    value = value.strip()
    if len(value) >= 2 and value[0] == '"' and value[-1] == '"':
        value = value[1:-1]
    return value


def parse_descriptor(text):
    """The fields of a VMDK descriptor, its extents (up to MAX_EXTENTS) and the counts of what was not kept."""
    d = {"fields": {}, "extents": [], "extents_total": 0, "ddb": {}, "ddb_other": 0, "lines_over_cap": False, "other_lines": 0}
    for number, raw in enumerate(text.split("\n"), 1):
        if number > MAX_DESC_LINES:
            d["lines_over_cap"] = True
            break
        line = raw.strip().rstrip("\r")
        if not line or line.startswith("#"):
            continue
        m = EXTENT.match(line)
        if m:
            d["extents_total"] += 1
            if len(d["extents"]) < MAX_EXTENTS:
                # the type is compared in upper case and shown as written: folding it first would hide a token's shape
                d["extents"].append({"access": m.group(1), "sectors": int(m.group(2)), "type": m.group(3).upper(), "type_raw": m.group(3),
                                     "name": m.group(4), "offset": int(m.group(5)) if m.group(5) else None, "line": number})
            continue
        m = DESC_KV.match(line)
        if not m:
            d["other_lines"] += 1
            continue
        key, value = m.group(1), unquote(m.group(2))
        if key.lower().startswith("ddb."):
            if key in KNOWN_DDB:
                d["ddb"][key] = value
            else:
                d["ddb_other"] += 1
        elif key.lower() in ("version", "encoding", "cid", "parentcid", "createtype", "parentfilenamehint", "isnativesnapshot"):
            d["fields"].setdefault(key.lower(), value)
        else:
            d["other_lines"] += 1
    return d


def descriptor_node(d, source, shown, fid):
    f = d["fields"]
    cid, pcid = f.get("cid"), f.get("parentcid")
    node = {"format": "vmdk", "version": shown(f.get("version"), fid, "version"), "create_type": f.get("createtype") if f.get("createtype") in CREATE_TYPES else shown(f.get("createtype"), fid, "createType"), "encoding": shown(f.get("encoding"), fid, "encoding"),
            "cid": cid_value(cid), "cid_raw": shown(cid, fid, "CID"),
            "parent_cid": cid_value(pcid), "parent_cid_raw": shown(pcid, fid, "parentCID"),
            "cid_note": "a CID is a 32-bit number written in hexadecimal (qemu-img writes it without leading zeros); it is shown as eight digits and compared as a number",
            "has_parent": cid_value(pcid) not in (None, "ffffffff"),
            "parent_hint": shown(f.get("parentfilenamehint"), fid, "parentFileNameHint"), "native_snapshot": shown(f.get("isnativesnapshot"), fid, "isNativeSnapshot"),
            "extents_total": d["extents_total"], "capacity_sectors_by_extents": sum(e["sectors"] for e in d["extents"]) if d["extents_total"] == len(d["extents"]) else None, "ddb": {k: shown(v, fid, k) for k, v in d["ddb"].items()}, "ddb_other_keys": d["ddb_other"], "descriptor_source": source}
    if cid and not CID_HEX.match(cid):
        node["problem"] = "CID is not 1 to 8 hexadecimal digits"
    if pcid and not CID_HEX.match(pcid):
        node["problem"] = "parentCID is not 1 to 8 hexadecimal digits"
    if node["has_parent"] and not node["parent_hint"]:
        node["problem"] = "a parentCID is recorded and no parentFileNameHint names the parent"
    if not node["has_parent"] and f.get("parentfilenamehint"):
        node["parent_hint_not_followed"] = "a parentFileNameHint is written and parentCID records no parent (ffffffff or none): the hint is not followed and no parent is looked for"
    return node


def parse_vmdk_text(fh, size, head):
    raw = head if size <= len(head) else head + read_at(fh, len(head), min(size, MAX_DESCRIPTOR) - len(head))
    over = size > MAX_DESCRIPTOR
    text = raw[:MAX_DESCRIPTOR].replace(b"\x00", b"\n").decode("utf-8", "replace")
    d = parse_descriptor(text)
    return d, over


def parse_vmdk_sparse(fh, size, head):
    if len(head) < 512:
        return {"state": "failed", "reason": "a sparse extent header is 512 bytes and the file is shorter"}
    (magic, version, flags, capacity, grain, doff, dsize, gtes, rgd, gd, overhead, unclean, c1, c2, c3, c4, comp) = struct.unpack("<4sIIQQQQIQQQBccccH", head[:79])
    info = {"format": "vmdk_sparse_extent", "sparse_version": version, "flags": "0x%08x" % flags, "capacity_sectors": capacity,
            "grain_size_sectors": grain, "descriptor_offset_sectors": doff, "descriptor_sectors": dsize, "overhead_sectors": overhead,
            "unclean_shutdown_flag": bool(unclean), "compress_algorithm": comp}
    markers = []
    if unclean:
        markers.append({"kind": "unclean_shutdown_flag", "observation": "the sparse extent header's uncleanShutdown byte is %d" % unclean,
                        "reading": "the extent was open for writing when the file was last written; a candidate for an interrupted write, a snapshot "
                                   "taken while running or a copy of a live file, not a verdict"})
    if flags & 1 and (c1, c2, c3, c4) != (b"\n", b" ", b"\r", b"\n"):
        markers.append({"kind": "newline_detection_mismatch", "observation": "the header's newline-detection bytes differ from the values the format fixes",
                        "reading": "the file may have been transferred in a mode that rewrites line ends; a candidate for an altered copy"})
    if version not in (1, 2, 3):
        return {"state": "unsupported", "reason": "sparse extent version %d is not one this tool reads" % version, "info": info, "markers": markers}
    desc = None
    if doff and dsize:
        want = min(dsize * 512, MAX_DESCRIPTOR)
        start = doff * 512
        if start >= size:
            return {"state": "failed", "reason": "the descriptor offset (%d sectors) is past the end of the file" % doff, "info": info, "markers": markers}
        data = read_at(fh, start, min(want, size - start))
        text = data.split(b"\x00", 1)[0].decode("utf-8", "replace")
        desc = parse_descriptor(text)
        info["descriptor_over_read_cap"] = dsize * 512 > MAX_DESCRIPTOR
    return {"state": "parsed", "info": info, "descriptor": desc, "markers": markers}


# ---- VHD -------------------------------------------------------------------------------------------------------------

VHD_FOOTER = struct.Struct(">8sIIQI4sI4sQQ4sII16sB")
VHD_TYPES = {2: "fixed", 3: "dynamic", 4: "differencing"}
VHD_EPOCH = 946684800  # 2000-01-01T00:00:00Z


def vhd_checksum_ok(raw, offset):
    zeroed = raw[:offset] + b"\x00\x00\x00\x00" + raw[offset + 4:]
    return (~sum(zeroed)) & 0xFFFFFFFF == struct.unpack(">I", raw[offset:offset + 4])[0]


def parse_vhd(fh, size, head):
    first = head[:512] if head[:8] == b"conectix" else None
    last = read_at(fh, size - 512, 512) if size >= 512 else b""
    footer = last if last[:8] == b"conectix" else first
    if footer is None or len(footer) < 512:
        return {"state": "failed", "reason": "no VHD footer (conectix) at the start or in the last 512 bytes"}
    (cookie, features, version, data_off, stamp, creator, creator_ver, host_os, original, current, geom, dtype, checksum, uid, saved) = VHD_FOOTER.unpack(footer[:85])
    info = {"format": "vhd", "disk_type": VHD_TYPES.get(dtype, "type %d (not read)" % dtype), "file_format_version": "0x%08x" % version,
            "footer_checksum_ok": vhd_checksum_ok(footer, 64), "unique_id": str(uuid.UUID(bytes=uid)).upper(),
            "created_utc": iso_utc(stamp, VHD_EPOCH), "created_raw": stamp, "created_epoch": "seconds since 2000-01-01T00:00:00Z",
            "original_size": original, "current_size": current, "saved_state": bool(saved),
            "creator_application": creator.decode("ascii", "replace"), "creator_version": "0x%08x" % creator_ver,
            "creator_host_os": host_os.decode("ascii", "replace"), "footer_location": "start" if footer is first and footer is not last else "end"}
    markers, damaged = [], []
    if not info["footer_checksum_ok"]:
        damaged.append("the VHD footer's checksum")
        markers.append({"kind": "vhd_footer_checksum_fail", "observation": "the footer's checksum does not match its bytes",
                        "reading": "the footer is damaged or was edited after it was written; its fields are shown as written and may be wrong"})
    if footer is first and last[:8] != b"conectix":
        damaged.append("the VHD footer at the end of the file is missing")
        markers.append({"kind": "vhd_footer_copy_missing", "observation": "the footer at the end of the file is missing (the last 512 bytes do not start with the cookie conectix); the copy at the start was read",
                        "reading": "the file was cut short, copied short, or its end footer was damaged; what the start copy records is shown as written, and the dynamic header and the parent names are read from the offsets it gives"})
    if saved:
        markers.append({"kind": "vhd_saved_state_flag", "observation": "the footer's Saved State byte is set",
                        "reading": "the disk was attached to a VM in a saved state when the footer was written; a candidate that the VM's saved state "
                                   "must be preserved with it"})
    if version >> 16 != 1:
        return {"state": "unsupported", "reason": "VHD file format version 0x%08x is not one this tool reads (major version 1 is)" % version, "info": info, "markers": markers}
    if dtype not in VHD_TYPES:
        return {"state": "unsupported", "reason": "disk type %d is not one this tool reads" % dtype, "info": info, "markers": markers}
    if dtype == 2:
        return {"state": "parsed", "info": info, "markers": markers, "damaged": damaged, "vhd": {"identity": info["unique_id"], "hints": [], "parent_identity": None}}
    if head[:8] == b"conectix" and last[:8] == b"conectix" and head[:512] != last[:512]:
        markers.append({"kind": "vhd_footer_copy_differs", "observation": "the footer copy at the start differs from the footer at the end",
                        "reading": "the two copies were not written together; a candidate for an interrupted write or an edit, not a verdict"})
    if data_off == 0xFFFFFFFFFFFFFFFF or data_off + 1024 > size:
        return {"state": "failed", "reason": "the footer's data offset does not point at a dynamic-disk header inside the file", "info": info, "markers": markers}
    hdr = read_at(fh, data_off, 1024)
    if len(hdr) < 1024 or hdr[:8] != b"cxsparse":
        return {"state": "failed", "reason": "no dynamic-disk header (cxsparse) at the footer's data offset", "info": info, "markers": markers}
    (_c, _d, table_off, hver, max_entries, block, hsum, pid, pstamp, _r, pname_raw) = struct.unpack(">8sQQIIII16sII512s", hdr[:576])
    pname = pname_raw.decode("utf-16-be", "replace").split("\x00", 1)[0]
    info.update({"dynamic_header_checksum_ok": vhd_checksum_ok(hdr, 36), "block_size": block, "max_table_entries": max_entries, "header_version": "0x%08x" % hver})
    if not info["dynamic_header_checksum_ok"]:
        damaged.append("the VHD dynamic-disk header's checksum")
        markers.append({"kind": "vhd_dynamic_header_checksum_fail", "observation": "the dynamic-disk header's checksum does not match its bytes",
                        "reading": "the header that holds the parent's id and name is damaged or was edited; the parent fields are shown as written and may be wrong"})
    if hver >> 16 != 1:
        return {"state": "unsupported", "reason": "VHD dynamic header version 0x%08x is not one this tool reads" % hver, "info": info, "markers": markers}
    hints, locators = [], []
    if dtype == 4:
        info["parent_unique_id"] = str(uuid.UUID(bytes=pid)).upper()
        info["parent_timestamp_utc"] = iso_utc(pstamp, VHD_EPOCH)
        info["parent_timestamp_raw"] = pstamp
        info["parent_name"] = pname
        if pname:
            hints.append(pname)
        for i in range(8):
            code, space, length, _res, loff = struct.unpack(">4sIIIQ", hdr[576 + 24 * i:576 + 24 * (i + 1)])
            if code == b"\x00\x00\x00\x00" or not length:
                continue
            entry = {"platform_code": code.decode("ascii", "replace"), "data_length": length, "data_offset": loff}
            if length <= 65536 and loff + length <= size:
                data = read_at(fh, loff, length)
                text = data.decode("utf-8" if code == b"MacX" else "utf-16-le", "replace").split("\x00", 1)[0]
                if text:
                    entry["path_present"] = True
                    hints.append(text)
            else:
                entry["problem"] = "the locator data is outside the file or over 64 KiB"
            locators.append(entry)
        info["parent_locators"] = len(locators)
    return {"state": "parsed", "info": info, "markers": markers, "damaged": damaged,
            "vhd": {"identity": info["unique_id"], "hints": hints, "parent_identity": info.get("parent_unique_id")}}


# ---- VHDX ------------------------------------------------------------------------------------------------------------

G_METADATA = "8B7CA206-4790-4B9A-B8FE-575F050F886E"
G_FILE_PARAMS = "CAA16737-FA36-4D43-B3B6-33F0AA44E76B"
G_DISK_ID = "BECA12AB-B2E6-4523-93EF-C309E000C746"
G_DISK_SIZE = "2FA54224-CD1B-4876-B211-5DBED83BF4B8"
G_PARENT_LOCATOR = "A8D35F2D-B30B-454D-ABF7-D3D84834AB0C"
G_LOCATOR_VHDX = "B04AEFB7-D19E-4A81-B789-25B8E9445913"
ZERO_GUID = "00000000-0000-0000-0000-000000000000"
GUID_TEXT = re.compile(r"[0-9A-F]{8}(?:-[0-9A-F]{4}){3}-[0-9A-F]{12}")


def vhdx_header(fh, offset, size):
    raw = read_at(fh, offset, 4096)
    if len(raw) < 4096 or raw[:4] != b"head":
        return None
    checksum = struct.unpack("<I", raw[4:8])[0]
    ok = crc32c(raw[:4] + b"\x00\x00\x00\x00" + raw[8:]) == checksum
    seq = struct.unpack("<Q", raw[8:16])[0]
    return {"offset": offset, "checksum_ok": ok, "sequence": seq, "file_write_guid": guid_text(raw[16:32]), "data_write_guid": guid_text(raw[32:48]),
            "log_guid": guid_text(raw[48:64]), "log_version": struct.unpack("<H", raw[64:66])[0], "version": struct.unpack("<H", raw[66:68])[0],
            "log_length": struct.unpack("<I", raw[68:72])[0], "log_offset": struct.unpack("<Q", raw[72:80])[0]}


def parse_vhdx(fh, size, head):
    markers = []
    headers = [h for h in (vhdx_header(fh, 65536, size), vhdx_header(fh, 131072, size)) if h]
    if not headers:
        return {"state": "failed", "reason": "no header with the head signature at 64 KiB or 128 KiB"}
    valid = [h for h in headers if h["checksum_ok"]]
    current = max(valid or headers, key=lambda h: h["sequence"])
    info = {"format": "vhdx", "headers_found": len(headers), "headers_checksum_ok": len(valid), "current_header_offset": current["offset"],
            "sequence_numbers": [h["sequence"] for h in headers], "file_write_guid": current["file_write_guid"], "data_write_guid": current["data_write_guid"],
            "log_guid": current["log_guid"], "log_length": current["log_length"], "version": current["version"]}
    damaged = []
    if not valid:
        damaged.append("both VHDX headers' CRC-32C")
        markers.append({"kind": "vhdx_headers_checksum_fail", "observation": "no header's CRC-32C matched",
                        "reading": "the headers are damaged or were edited; the current header was chosen by sequence number alone"})
    elif len(valid) < 2:
        damaged.append("one VHDX header's CRC-32C or signature")
        markers.append({"kind": "vhdx_header_copy_damaged", "observation": "%d of the two VHDX headers has a signature and a CRC-32C that hold; the header at %d KiB was taken as current" % (len(valid), current["offset"] // 1024),
                        "reading": "one copy is damaged, edited or missing; which header is current decides which DataWriteGuid a child's parent linkage is compared with, so the identity check below rests on the one copy that holds"})
    if current["version"] != 1:
        return {"state": "unsupported", "reason": "VHDX header version %d is not one this tool reads" % current["version"], "info": info, "markers": markers}
    if current["log_guid"] != ZERO_GUID:
        markers.append({"kind": "vhdx_log_guid_set", "observation": "the current header's LogGuid is not zero (log length %d)" % current["log_length"],
                        "reading": "a log is present; whether it holds entries that were not replayed is not read here, so this is a candidate for an "
                                   "interrupted write and also what a log in use looks like"})
    # MS-VHDX keeps two copies of the region table (192 KiB and 256 KiB): the first whose signature and CRC-32C hold is read
    copies = []
    for offset in (196608, 262144):
        raw = read_at(fh, offset, 65536)
        ok = len(raw) == 65536 and raw[:4] == b"regi" and crc32c(raw[:4] + b"\x00\x00\x00\x00" + raw[8:]) == struct.unpack("<I", raw[4:8])[0]
        copies.append((offset, raw, ok))
    good = [c for c in copies if c[2]]
    signed = [c for c in copies if len(c[1]) >= 16 and c[1][:4] == b"regi"]
    if not signed:
        return {"state": "failed", "reason": "no region table (regi) at 192 KiB or at 256 KiB", "info": info, "markers": markers}
    offset, region, _ok = (good or signed)[0]
    info["region_table_offset"] = offset
    info["region_table_checksum_ok"] = bool(good) and offset == good[0][0]
    info["region_table_copies_valid"] = len(good)
    if not good:
        damaged.append("both VHDX region tables' CRC-32C")
        markers.append({"kind": "vhdx_region_table_checksum_fail", "observation": "neither copy of the region table has a CRC-32C that matches",
                        "reading": "the region table (where the metadata is) is damaged or was edited; the metadata was read from the copy at %d KiB as written" % (offset // 1024)})
    elif len(good) < len(copies):
        markers.append({"kind": "vhdx_region_table_copy_damaged", "observation": "one copy of the region table does not hold (signature or CRC-32C); the copy at %d KiB does and was read" % (offset // 1024),
                        "reading": "a damaged or edited copy; the file can still be read from the other"})
    count = struct.unpack("<I", region[8:12])[0]
    meta_off = meta_len = None
    for i in range(min(count, 2047)):
        e = region[16 + 32 * i:48 + 32 * i]
        if len(e) < 32:
            break
        if guid_text(e[:16]) == G_METADATA:
            meta_off, meta_len = struct.unpack("<QI", e[16:28])
    if meta_off is None or meta_off + 65536 > size:
        return {"state": "failed", "reason": "the region table names no metadata region inside the file", "info": info, "markers": markers}
    table = read_at(fh, meta_off, 65536)
    if table[:8] != b"metadata":
        return {"state": "failed", "reason": "no metadata table at the region the region table names", "info": info, "markers": markers}
    items = {}
    for i in range(min(struct.unpack("<H", table[10:12])[0], 2047)):
        e = table[32 + 32 * i:64 + 32 * i]
        if len(e) < 32:
            break
        items[guid_text(e[:16])] = struct.unpack("<II", e[16:24])
    # MS-VHDX: a child's parent_linkage (and parent_linkage2) holds the DataWriteGuid of the parent's header, which the
    # parent changes the first time it is written after it was opened; the VirtualDiskId stays the same through every
    # write and is kept here as information only. So the identity a child is held against is the DataWriteGuid of the
    # parent's current header (the valid one with the higher sequence number).
    vx = {"identity": current["data_write_guid"], "identity_field": "DataWriteGuid of the current header", "hints": [], "parent_identity": None, "parent_identity_2": None}
    info["linkage_identity"] = current["data_write_guid"]
    info["linkage_identity_note"] = ("a child's parent_linkage is compared with this disk's DataWriteGuid (MS-VHDX); the VirtualDiskId is information "
                                     "and is not what a child records")
    if G_FILE_PARAMS in items:
        off, length = items[G_FILE_PARAMS]
        raw = read_at(fh, meta_off + off, 8) if length >= 8 else b""
        if len(raw) == 8:
            block, flags = struct.unpack("<II", raw)
            info["block_size"] = block
            info["has_parent"] = bool(flags & 2)
            info["leave_blocks_allocated"] = bool(flags & 1)
    if G_DISK_SIZE in items:
        off, length = items[G_DISK_SIZE]
        raw = read_at(fh, meta_off + off, 8) if length >= 8 else b""
        if len(raw) == 8:
            info["virtual_size"] = struct.unpack("<Q", raw)[0]
    if G_DISK_ID in items:
        off, length = items[G_DISK_ID]
        raw = read_at(fh, meta_off + off, 16) if length >= 16 else b""
        if len(raw) == 16:
            info["virtual_disk_id"] = guid_text(raw)
    if G_PARENT_LOCATOR in items:
        off, length = items[G_PARENT_LOCATOR]
        raw = read_at(fh, meta_off + off, min(length, 1 << 20))
        if len(raw) >= 20:
            ltype = guid_text(raw[:16])
            kv = struct.unpack("<H", raw[18:20])[0]
            info["parent_locator_type"] = ltype
            pairs = {}
            if ltype == G_LOCATOR_VHDX:
                for i in range(min(kv, 1024)):
                    e = raw[20 + 12 * i:32 + 12 * i]
                    if len(e) < 12:
                        break
                    ko, vo, kl, vl = struct.unpack("<IIHH", e)
                    if ko + kl <= len(raw) and vo + vl <= len(raw):
                        pairs[raw[ko:ko + kl].decode("utf-16-le", "replace")] = raw[vo:vo + vl].decode("utf-16-le", "replace")
                for key in ("relative_path", "absolute_win32_path", "volume_path"):
                    if pairs.get(key):
                        info["parent_" + key] = pairs[key]
                        if key != "volume_path":
                            vx["hints"].append(pairs[key])
                for key, slot in (("parent_linkage", "parent_identity"), ("parent_linkage2", "parent_identity_2")):
                    if pairs.get(key):
                        text = pairs[key].strip("{}").upper()
                        if GUID_TEXT.fullmatch(text):
                            vx[slot] = info[key] = text
                        else:
                            info[key + "_problem"] = "the value is not a GUID (%d characters): not compared" % len(pairs[key])
                info["parent_locator_keys"] = sorted(k for k in pairs if k in ("parent_linkage", "parent_linkage2", "relative_path", "volume_path", "absolute_win32_path"))
                info["parent_locator_other_keys"] = len(pairs) - len(info["parent_locator_keys"])
            else:
                info["parent_locator_note"] = "a locator of another type: not read"
    if info.get("has_parent") and not (vx["parent_identity"] or vx["hints"]):
        info["problem"] = "the file parameters say a parent exists and the parent locator names none"
    return {"state": "parsed", "info": info, "markers": markers, "damaged": damaged, "vhdx": vx}


# ---- QCOW2 -----------------------------------------------------------------------------------------------------------

QCOW_EXT_NAMES = {0xE2792ACA: "backing_file_format", 0x6803F857: "feature_name_table", 0x0537BE77: "full_disk_encryption_header",
                  0x23852875: "bitmaps", 0x44415441: "external_data_file_name"}
QCOW_INCOMPAT = ((0, "dirty"), (1, "corrupt"), (2, "external_data_file"), (3, "compression_type"), (4, "extended_l2_entries"))


def parse_qcow2(fh, size, head, snapshot_sink, max_snapshots, clock):
    if len(head) < 72:
        return {"state": "failed", "reason": "a QCOW2 header is at least 72 bytes and the file is shorter"}
    (magic, version, boff, bsize, cbits, vsize, crypt, l1size, l1off, rcoff, rcclusters, nsnap, soff) = struct.unpack(">4sIQIIQIIQQIIQ", head[:72])
    info = {"format": "qcow2", "version": version, "virtual_size": vsize, "cluster_bits": cbits, "encryption_method_field": crypt,
            "backing_file_offset": boff, "snapshots_declared": nsnap}
    markers = []
    if version not in (2, 3):
        return {"state": "unsupported", "reason": "QCOW version %d is not one this tool reads" % version, "info": info, "markers": markers}
    if not 9 <= cbits <= 21:
        return {"state": "failed", "reason": "cluster_bits %d is outside 9 to 21" % cbits, "info": info, "markers": markers}
    header_len = 72
    if version == 3:
        if len(head) < 104:
            return {"state": "failed", "reason": "a version 3 header is at least 104 bytes and the file is shorter", "info": info, "markers": markers}
        incompat, compat, autoclear, rorder, header_len = struct.unpack(">QQQII", head[72:104])
        info.update({"incompatible_features": "0x%x" % incompat, "compatible_features": "0x%x" % compat, "autoclear_features": "0x%x" % autoclear,
                     "refcount_order": rorder, "header_length": header_len})
        flags = [name for bit, name in QCOW_INCOMPAT if incompat & (1 << bit)]
        info["incompatible_feature_names"] = flags
        if incompat >> 5:
            info["incompatible_unknown_bits"] = "0x%x" % (incompat >> 5 << 5)
        if incompat & 1:
            markers.append({"kind": "qcow2_dirty_bit", "observation": "incompatible feature bit 0 (dirty) is set",
                            "reading": "the image's reference counts may be stale because it was not closed cleanly; a candidate for an interrupted "
                                       "write or a copy of a live image, not a verdict"})
        if incompat & 2:
            markers.append({"kind": "qcow2_corrupt_bit", "observation": "incompatible feature bit 1 (corrupt) is set",
                            "reading": "the image was marked corrupt by the program that last wrote it"})
    # header extensions
    exts, backing_format, ext_data = [], None, None
    ext_start = header_len if version == 3 else 72
    cluster = 1 << cbits
    window = read_at(fh, ext_start, min(max(0, cluster - ext_start), 1 << 20)) if ext_start < size else b""
    pos, n = 0, 0
    while pos + 8 <= len(window) and n < 64:
        etype, elen = struct.unpack(">II", window[pos:pos + 8])
        if etype == 0:
            break
        data = window[pos + 8:pos + 8 + elen]
        name = QCOW_EXT_NAMES.get(etype, "0x%08x" % etype)
        exts.append(name)
        if etype == 0xE2792ACA:
            backing_format = data.decode("utf-8", "replace")
        elif etype == 0x44415441:
            ext_data = data.decode("utf-8", "surrogateescape")
        pos += 8 + ((elen + 7) & ~7)
        n += 1
    info["header_extensions"] = exts
    if backing_format is not None:
        info["backing_format"] = backing_format
    if ext_data is not None:
        info["external_data_file"] = ext_data
    hints = []
    if boff:
        if bsize > 1023:
            info["problem"] = "the backing file name is declared %d bytes; the format allows 1023" % bsize
        raw = read_at(fh, boff, min(bsize, 4096)) if boff < size else b""
        if len(raw) < min(bsize, 4096):
            info["problem"] = "the backing file name lies outside the file"
        else:
            name = decode(raw)
            info["backing_file"] = name
            hints.append(name)
    # internal snapshots, streamed
    snaps = {"declared": nsnap, "read": 0, "stopped": None}
    if nsnap:
        pos = soff
        if soff == 0 or soff >= size:
            snaps["stopped"] = "the snapshot table offset is %s" % ("0" if soff == 0 else "outside the file")
        else:
            for index in range(min(nsnap, max_snapshots)):
                clock.check(1024)
                raw = read_at(fh, pos, 40)
                if len(raw) < 40:
                    snaps["stopped"] = "the file ends inside entry %d" % index
                    break
                (l1o, l1s, idsz, namesz, dsec, dnsec, vmclock, vmstate, extra) = struct.unpack(">QIHHIIQII", raw)
                if idsz == 0:
                    snaps["stopped"] = "entry %d has an empty id string: the table ends or is damaged here" % index
                    break
                if extra > 65536 or pos + 40 + extra + idsz + namesz > size:
                    snaps["stopped"] = "entry %d declares sizes that run past the file or over 64 KiB of extra data" % index
                    break
                body = read_at(fh, pos + 40, extra + idsz + namesz)
                sid = decode(body[extra:extra + idsz])
                sname = decode(body[extra + idsz:extra + idsz + namesz])
                snapshot_sink({"index": index, "id": sid, "name": sname, "date_utc": iso_utc(dsec), "date_raw": dsec, "date_nsec": dnsec,
                               "vm_clock_ns": vmclock, "vm_state_size": vmstate, "l1_size": l1s, "l1_table_offset": l1o})
                snaps["read"] += 1
                pos += (40 + extra + idsz + namesz + 7) & ~7
            if snaps["read"] < nsnap and not snaps["stopped"]:
                snaps["stopped"] = "max_snapshots (%d) was reached" % max_snapshots
    info["internal_snapshots"] = snaps
    data_file = {"named": ext_data, "feature_bit": bool(version == 3 and "external_data_file" in info.get("incompatible_feature_names", []))}
    out = {"state": "parsed", "info": info, "markers": markers, "qcow2": {"hints": hints, "backing_format": backing_format, "data_file": data_file}}
    if snaps["read"] < nsnap:
        # the table declares more snapshots than were read: the image is not read whole, whatever stopped the read
        out["state"] = "partial"
        out["reason"] = "the header declares %d internal snapshot(s) and %d were read: %s" % (nsnap, snaps["read"], snaps["stopped"])
    return out


# ---- VMX and VMSD ----------------------------------------------------------------------------------------------------

CONFIG_KV = re.compile(r'^\s*([A-Za-z0-9_.:\-]+)\s*=\s*"(.*)"\s*$')
DISK_KEY = re.compile(r"^(scsi|ide|sata|nvme)\d+:\d+\.filename$", re.I)
SNAP_KEY = re.compile(r"^snapshot(\d+)\.(.+)$", re.I)


def read_config(fh, size):
    """Yield (line number, key, value) of the key = "value" lines of a .vmx or .vmsd, a line at a time."""
    n = 0
    while True:
        raw = fh.readline(MAX_CONFIG_LINE + 1)
        if not raw:
            return
        n += 1
        if n > MAX_CONFIG_LINES:
            yield n, None, "line cap"
            return
        if len(raw) > MAX_CONFIG_LINE:
            while raw and not raw.endswith(b"\n"):
                raw = fh.readline(MAX_CONFIG_LINE)
            yield n, None, "over-long line"
            continue
        m = CONFIG_KV.match(raw.decode("utf-8", "surrogateescape").rstrip("\r\n"))
        if m:
            yield n, m.group(1), m.group(2)


def parse_vmx(fh, size):
    disks, problems, keys = [], [], 0
    for n, key, value in read_config(fh, size):
        if key is None:
            problems.append(value)
            continue
        keys += 1
        if DISK_KEY.match(key):
            disks.append({"key": key, "file": value, "line": n})
    return {"state": "parsed", "info": {"format": "vmx", "keys_read": keys, "disk_entries": len(disks), "note": WITHHELD_CONFIG_NOTE},
            "vmx": {"disks": disks, "problems": problems}}


def parse_vmsd(fh, size):
    entries = collections.OrderedDict()
    top, over, problems = {}, 0, []
    for n, key, value in read_config(fh, size):
        if key is None:
            problems.append(value)
            continue
        low = key.lower()
        if low in ("snapshot.numsnapshots", "snapshot.current", "snapshot.lastuid"):
            top[low.split(".", 1)[1]] = value
            continue
        m = SNAP_KEY.match(key)
        if not m:
            continue
        idx = int(m.group(1))
        if idx not in entries:
            if len(entries) >= MAX_SNAPSHOT_ENTRIES:
                over += 1
                continue
            entries[idx] = {"index": idx, "line": n, "disks": {}}
        sub, e = m.group(2), entries[idx]
        sl = sub.lower()
        dm = re.match(r"^disk(\d+)\.(.+)$", sl)
        if dm:
            if dm.group(2) == "filename":
                e["disks"][int(dm.group(1))] = value
        elif sl in ("uid", "filename", "displayname", "parent", "numdisks", "createtimehigh", "createtimelow", "type", "description", "id"):
            e[sl] = value
    return {"state": "parsed", "info": {"format": "vmsd", "snapshots_listed": len(entries), "snapshot_entries_over_cap": over,
                                          "numsnapshots": top.get("numsnapshots"), "current": top.get("current"), "lastuid": top.get("lastuid")},
            "vmsd": {"entries": list(entries.values()), "over": over, "top": top, "problems": problems}}


# ---- classification --------------------------------------------------------------------------------------------------

def classify(rec, fh, size):
    head = fh.read(min(size, 65536))
    name = rec["rel"].lower()
    if head[:4] == b"KDMV":
        return "vmdk_sparse", head
    if head[:4] == b"COWD":
        return "vmdk_cowd", head
    if head[:4] == b"QFI\xfb":
        return "qcow2", head
    if head[:8] == b"vhdxfile":
        return "vhdx", head
    if head[:8] == b"conectix":
        return "vhd", head
    if size >= 512:
        fh.seek(size - 512)
        if fh.read(8) == b"conectix":
            return "vhd", head
    text = head[3:] if head[:3] == b"\xef\xbb\xbf" else head
    if text.lstrip()[:24].startswith(b"# Disk DescriptorFile"):
        return "vmdk_descriptor", head
    if name.endswith(".vmsd"):
        return "vmsd", head
    if name.endswith(".vmx"):
        return "vmx", head
    if name.endswith(".lck") or posixpath.basename(name).startswith(".lck-"):
        return "lock_file", head
    return "other", head


# ---- the run ---------------------------------------------------------------------------------------------------------

def qemu_format(kind):
    return {"vmdk": "vmdk", "vhd": "vpc", "vhdx": "vhdx", "qcow2": "qcow2"}.get(kind)


# qemu's names for formats, as a QCOW2 backing-format extension writes them, against this tool's
QEMU_FORMAT_NAMES = {"vpc": "vhd", "vmdk": "vmdk", "vhdx": "vhdx", "qcow2": "qcow2", "raw": "raw", "file": "raw", "host_device": "raw"}


def run_qemu(path, kind, seconds):
    fmt = qemu_format(kind)
    argv = ["qemu-img", "info", "--output=json", "-f", fmt, path]
    code, out, err, timed_out = preflight(argv, seconds)
    result = {"command_format": fmt, "exit_code": code, "timed_out": timed_out}
    if code is None and not timed_out:
        result["available"] = False
        result["error"] = brief(err.decode("utf-8", "replace"), 300)
        return result
    result["available"] = True
    if timed_out or code != 0:
        result["error"] = brief(err.decode("utf-8", "replace"), 400) or ("timed out" if timed_out else "exit code %s, nothing on stderr" % code)
        return result
    try:
        data = json.loads(out[:1 << 20].decode("utf-8", "replace"))
        result.update({"format": data.get("format"), "virtual_size": data.get("virtual-size"), "actual_size": data.get("actual-size"),
                       "backing_filename": seal_head(str(data["backing-filename"]), "text") if data.get("backing-filename") else None,
                       "backing_filename_format": data.get("backing-filename-format"), "dirty_flag": data.get("dirty-flag")})
    except (ValueError, AttributeError):
        result["error"] = "qemu-img printed output that is not JSON"
    return result


CHAIN_ORDER = ("cycle", "too_deep", "broken", "parent_unreadable", "identity_not_compared", "identity_mismatch", "extent_missing", "data_file_missing")
CHAIN_DETAIL = {
    "broken": "the parent %s names is not in the set",
    "parent_unreadable": "the parent of %s is in the set and could not be read as a disk (failed, unsupported, a bare extent or another kind of file): its identity was not compared",
    "identity_not_compared": "the identity of %s's parent could not be compared: one side records none, a value that is not one, or the parent is a disk of another format",
    "identity_mismatch": "the identity %s records for its parent is not the identity the parent file carries",
    "extent_missing": "an extent %s's descriptor needs is missing from the set or shorter than the descriptor says",
    "data_file_missing": "the external data file %s's header names is not in the set",
}


def main():
    STATE["last_word"] = stop_word
    install_signal_handlers()
    args = read_args()
    root = want_str(args, "root")
    paths = want_str_list(args, "paths", 100000)
    if root is None and not paths:
        fail("name the evidence: root is a directory of descriptors and images, paths is a list of files")
    limit = want_int(args, "limit", DEFAULT_LIMIT, 1, 100000)
    max_files = want_int(args, "max_files", 20000, 1, 200000)
    max_entries = want_int(args, "max_entries", 200000, 1, 2000000)
    max_depth = want_int(args, "max_depth", 16, 1, 64)
    max_snapshots = want_int(args, "max_snapshots", DEFAULT_MAX_SNAPSHOTS, 1, 1000000)
    max_chain = want_int(args, "max_chain_depth", 10000, 1, 1000000)
    seconds = want_seconds(args, "max_seconds", DEFAULT_SECONDS, MAX_SECONDS)
    qemu_mode = args.get("qemu_img", "off")
    if qemu_mode not in ("off", "auto", "require"):
        fail("qemu_img must be off, auto or require")
    qemu_max = want_int(args, "qemu_img_max_images", 50, 1, 1000)
    write_text = want_flag(args, "write_text")
    try:
        values = TextFile("chain-values.jsonl", write_text, "JSON Lines, mode 0600: record_type original, where (a source id and the field), field, value (the "
                          "original text of a name, hint or snapshot name the answer shows withheld or shortened)")
    except TextRefused as exc:
        fail(str(exc))
    shown = Shower(values)
    bind_run(values, seconds)
    # The reading stops at four fifths of max_seconds; the rest is for writing the rows and the answer, which stop at
    # max_seconds itself, so that the call ends near the time asked for even when a stop leaves many rows to write.
    clock = Clock(seconds * 0.8)
    out_clock = Clock(seconds)
    at_limit = "max_seconds (%s; the reading stops at four fifths of it)" % seconds
    files = FileSet(shown)
    partial = []
    try:
        files.walk(root, paths, max_files, max_entries, max_depth, clock)
    except Overtime:
        partial.append("the walk stopped at %s: the files after the last one listed were not reached" % at_limit)
    if files.truncated:
        partial.append(files.truncated)
    index = Index(files.files)

    pages = {k: LosslessPage(TOOL, k, limit) for k in ("sources", "disks", "edges", "chains", "extents", "snapshot_database", "internal_snapshots", "markers")}
    nodes, vmx_list, vmsd_list = {}, [], []
    kinds = collections.Counter()
    kind_of = {}
    other_ext = collections.Counter()
    state_counts = collections.Counter()
    problems = []                      # files recognised and not read
    damaged = []                       # files read whose header checksum does not hold: (id, what)
    config_total = {"disks": 0, "snapshots": 0, "dropped": 0}

    def marker(kind, ids, observation, reading, corroborate=None, **extra):
        """A marker row: every text in it is shown through the shape check, whatever was put into it."""
        row = {"kind": kind, "source_ids": ids, "observation": shown(observation, "marker", kind), "reading": shown(reading, "marker", kind),
               "corroborate": shown(corroborate or "the VM's own records of the operation (task or event log), the file times and a second copy", "marker", kind)}
        for key, value in extra.items():
            row[key] = shown(value, "marker", key) if isinstance(value, str) else value
        pages["markers"].add(row)

    def snapshot_sink_for(fid):
        def sink(row):
            row = dict(row)
            row["source_id"] = fid
            row["id"] = shown(row["id"], fid, "snapshot id")
            row["name"] = shown(row["name"], fid, "snapshot name")
            pages["internal_snapshots"].add(row)
        return sink

    disks, extent_targets, extents_over = {}, {}, []
    node_issue = collections.defaultdict(dict)     # disk id -> {issue kind: the disk it is about}

    def build_disk(fid, res):
        rec = res["rec"]
        kind = res["row"]["kind"]
        d = {"id": fid, "file": res["row"]["file"], "rel": rec["rel"], "state": res["state"], "has_identity": False, "own_id": None, "parent_id": None, "hints": []}
        if kind == "vmdk_cowd":
            d["role"] = "extent_only"
            disks[fid] = d
            return
        if kind in ("vmdk_descriptor", "vmdk_sparse"):
            desc = res.pop("descriptor", None)
            if kind == "vmdk_sparse" and desc is None:
                d["role"] = "extent_only"
                disks[fid] = d
                return
            if desc is None:
                disks[fid] = d
                return
            node = descriptor_node(desc, "embedded in a sparse extent" if kind == "vmdk_sparse" else "text descriptor", shown, fid)
            if kind == "vmdk_sparse":
                node["sparse_header"] = res["row"]["info"]
            d.update(format="vmdk", has_identity=node["cid"] is not None, own_id=node["cid"], parent_id=node["parent_cid"] if node["has_parent"] else None,
                     hints=[desc["fields"]["parentfilenamehint"]] if desc["fields"].get("parentfilenamehint") else [], has_parent=node["has_parent"], detail=node)
            if node.get("problem"):
                marker("descriptor_problem", [fid], node["problem"], "the descriptor is inconsistent as written; the chain through it is not read further than it says")
            for i, ext in enumerate(desc["extents"]):
                clock.check(256)
                target, how = (None, "no_name")
                if ext["name"] is not None and ext["type"] not in NOT_A_FILE_EXTENT:
                    target, how = index.resolve(rec["rel"], ext["name"].replace('\\"', '"'))
                erow = {"descriptor_id": fid, "index": i, "line": ext["line"], "access": ext["access"], "sectors": ext["sectors"],
                        "type": ext["type"] if ext["type"] in KNOWN_EXTENT_TYPES else shown(ext["type_raw"], fid, "extent type"),
                        "file": shown(ext["name"], fid, "extent file name") if ext["name"] is not None else None, "offset_sectors": ext["offset"],
                        "found": target["id"] if target else None, "resolution": how}
                if ext["name"] is None or ext["type"] in NOT_A_FILE_EXTENT:
                    erow["state"] = "not_a_file_extent"
                elif target is None:
                    erow["state"] = "missing"
                    node_issue[fid].setdefault("extent_missing", fid)
                    marker("extent_missing", [fid], "extent %d of the descriptor names a file that is not in the set (%s)" % (i, how),
                           "the disk cannot be read whole from this set; whether the file existed is not shown", line=ext["line"])
                else:
                    if target["id"] != fid:                # a monolithic sparse disk names its own file as its extent
                        extent_targets[target["id"]] = fid
                    if ext["type"] in ("FLAT", "VMFS"):
                        expected = (ext["sectors"] + (ext["offset"] or 0)) * 512
                        erow["expected_size_at_least"] = expected
                        erow["actual_size"] = target["size"]
                        erow["state"] = "short" if target["size"] < expected else "present"
                        if erow["state"] == "short":
                            node_issue[fid].setdefault("extent_missing", fid)
                            marker("extent_short", [fid, target["id"]], "extent %d is %d bytes and the descriptor needs at least %d" % (i, target["size"], expected),
                                   "the extent file is smaller than the descriptor says: truncated, partly copied or rewritten", line=ext["line"])
                    else:
                        erow["state"] = "present"
                        erow["size_check"] = "not made: a sparse extent has no size to compare"
                pages["extents"].add(erow)
            if desc["extents_total"] > len(desc["extents"]):
                node_issue[fid].setdefault("extent_missing", fid)
                extents_over.append(fid)
        elif kind == "vhd":
            v = res.get("vhd")
            if v:
                d.update(format="vhd", has_identity=True, own_id=v["identity"], parent_id=v["parent_identity"], hints=v["hints"], has_parent=res["row"]["info"].get("disk_type") == "differencing", detail=res["row"]["info"])
        elif kind == "vhdx":
            v = res.get("vhdx")
            if v:
                d.update(format="vhdx", has_identity=bool(v["identity"]), own_id=v["identity"], parent_id=v["parent_identity"], parent_id_2=v.get("parent_identity_2"),
                         hints=v["hints"], has_parent=bool(res["row"]["info"].get("has_parent")), detail=res["row"]["info"])
        elif kind == "qcow2":
            v = res.get("qcow2")
            if v:
                d.update(format="qcow2", has_identity=False, hints=v["hints"], has_parent=bool(v["hints"]), detail=res["row"]["info"], backing_format=v.get("backing_format"))
                data_file = v.get("data_file") or {}
                d["external_data_file"] = bool(data_file.get("named") or data_file.get("feature_bit"))
                if data_file.get("named"):
                    target, how = index.resolve(rec["rel"], data_file["named"])
                    d["detail"]["external_data_file_found"] = target["id"] if target else None
                    d["detail"]["external_data_file_resolution"] = how
                    if target is None:
                        node_issue[fid].setdefault("data_file_missing", fid)
                        marker("external_data_file_missing", [fid], "the header names an external data file that is not in the set (%s)" % how,
                               "the guest data of this image lives in that file; without it the image cannot be read whole from this set")
        disks[fid] = d

    examined = 0
    try:
        for rec in files.files:
            clock.check()
            fh, why = open_regular(rec["path"])
            if fh is None:
                files.note("unreadable", rec["rel"] + ": " + (why or ""))
                kind_of[rec["id"]] = "unreadable"
                continue
            with fh:
                kind, head = classify(rec, fh, rec["size"])
                kinds[kind] += 1
                kind_of[rec["id"]] = kind
                if kind == "other":
                    ext = ext_of(rec["rel"])
                    other_ext[ext if (ext in other_ext or len(other_ext) < 2000) else "(other extensions)"] += 1
                    continue
                examined += 1
                row = {"source_id": rec["id"], "file": shown(rec["rel"], rec["id"], "file"), "size": rec["size"], "kind": kind}
                try:
                    if kind == "vmdk_sparse":
                        res = parse_vmdk_sparse(fh, rec["size"], head)
                    elif kind == "vmdk_descriptor":
                        d, over = parse_vmdk_text(fh, rec["size"], head)
                        res = {"state": "parsed", "info": {"format": "vmdk"}, "descriptor": d}
                        if over:
                            res["state"] = "partial"
                            res["reason"] = "the descriptor file is over %d bytes: read to that point" % MAX_DESCRIPTOR
                    elif kind == "vmdk_cowd":
                        res = {"state": "parsed", "info": {"format": "vmdk_cowd_extent", "header_read": False,
                                                          "note": "a COWD sparse extent (the delta of a VMFS sparse snapshot) is recognised by its first four bytes; its header is not read, because the chain is in the descriptor that names it"}}
                    elif kind == "vhd":
                        res = parse_vhd(fh, rec["size"], head)
                    elif kind == "vhdx":
                        res = parse_vhdx(fh, rec["size"], head)
                    elif kind == "qcow2":
                        res = parse_qcow2(fh, rec["size"], head, snapshot_sink_for(rec["id"]), max_snapshots, clock)
                    elif kind in ("vmx", "vmsd"):
                        if rec["size"] > MAX_CONFIG_BYTES:
                            res = {"state": "failed", "reason": "a configuration file over %d bytes is named and not read" % MAX_CONFIG_BYTES, "info": {"format": kind},
                                   "vmx": {"disks": [], "problems": []}, "vmsd": {"entries": [], "over": 0, "top": {}, "problems": []}}
                        else:
                            fh.seek(0)
                            res = parse_vmx(fh, rec["size"]) if kind == "vmx" else parse_vmsd(fh, rec["size"])
                    elif kind == "lock_file":
                        res = {"state": "parsed", "info": {"format": "lock_file"},
                               "markers": [{"kind": "lock_artefact", "observation": "a file named like a lock file is present",
                                            "reading": "a lock is made while a program holds the disk or the VM; it can be a copy of a live VM's directory or a left-over after a crash: a candidate"}]}
                    else:
                        res = {"state": "unsupported", "reason": "unknown kind"}
                except (struct.error, ValueError, OverflowError, MemoryError) as exc:
                    res = {"state": "failed", "reason": "the structure could not be read (%s)" % describe(exc)}
                except OSError as exc:
                    res = {"state": "failed", "reason": "a read failed (%s)" % describe(exc)}
            state_counts[res["state"]] += 1
            row["state"] = res["state"]
            if res.get("reason"):
                row["reason"] = res["reason"]
            if res["state"] in ("failed", "unsupported", "partial"):
                problems.append(rec["id"])
            net = make_net(shown, rec["id"])
            row["info"] = net(res.get("info") or {})
            for m in res.get("markers") or []:
                marker(m["kind"], [rec["id"]], m["observation"], m["reading"])
            for what in res.get("damaged") or []:
                damaged.append((rec["id"], what))
            res["row"] = row
            res["rec"] = rec
            pages["sources"].add(row)
            if kind == "vmx":
                res.setdefault("vmx", {"disks": [], "problems": []})
                config_total["disks"] += len(res["vmx"]["disks"])
                if config_total["disks"] > MAX_CONFIG_ENTRIES_TOTAL:
                    res["vmx"]["disks"] = []
                    config_total["dropped"] += 1
                vmx_list.append(res)
            elif kind == "vmsd":
                res.setdefault("vmsd", {"entries": [], "over": 0, "top": {}, "problems": []})
                config_total["snapshots"] += len(res["vmsd"]["entries"])
                if config_total["snapshots"] > MAX_CONFIG_ENTRIES_TOTAL:
                    res["vmsd"]["entries"] = []
                    config_total["dropped"] += 1
                vmsd_list.append(res)
            elif kind in ("vmdk_descriptor", "vmdk_sparse", "vmdk_cowd", "vhd", "vhdx", "qcow2"):
                res["rec"], res["row"] = rec, row
                build_disk(rec["id"], res)
                nodes[rec["id"]] = {"rec": rec, "row": {"kind": kind}}
    except Overtime:
        partial.append("the examination stopped at %s: the files after the last one listed in sources were not read" % at_limit)

    parent_of, edge_of = {}, {}
    too_deep_leaves = []               # chain rows the max_chain_depth limit stopped
    depth, base, state_of, first_issue, cycle_of = {}, {}, {}, {}, {}
    chain_summary = collections.Counter()
    phase = "the parent edges"
    try:
        # ---- edges: one per disk that records a parent ----------------------------------------------------------------
        for fid, d in disks.items():
            clock.check(256)
            if d.get("role") == "extent_only" or not d.get("format") or not d.get("has_parent"):
                continue
            target, how, resolved = None, "no_name", []
            for h in d["hints"]:
                t, w = index.resolve(d["rel"], h)
                resolved.append((t, w))
                if target is None and t:
                    target, how = t, w
            if target is None and resolved:
                how = resolved[0][1]
            edge = {"child": fid, "parent_name": shown(d["hints"][0], fid, "parent name") if d["hints"] else None, "names_tried": len(d["hints"]),
                    "resolved_to": target["id"] if target else None, "resolution": how, "id_check": "not_available", "format": d["format"]}
            if d["format"] in ("vhd", "vhdx") and len(d["hints"]) > 1:
                found = sorted({t["id"] for t, _w in resolved if t})
                names = {posixpath.basename(h.replace("\\", "/")).casefold() for h in d["hints"]}
                if len(found) > 1 or len(names) > 1:
                    edge["parent_names_disagree"] = True
                    marker("parent_names_disagree", [fid] + found, "the %d parent names the child records (the header's name and its locators) do not name one file: %d different file name(s), %d file(s) of the set" % (len(d["hints"]), len(names), len(found)),
                           "the locators were written at different times or edited; which of them the hypervisor would follow is not decided here (the first name that resolves is used)")
            pkind = kind_of.get(target["id"]) if target else None
            pdisk = disks.get(target["id"]) if target else None
            if target is None:
                edge["parent_state"] = "not in the set"
                node_issue[fid].setdefault("broken", fid)
            elif pdisk is None or pdisk.get("role") == "extent_only" or not pdisk.get("format") or pdisk["state"] in ("failed", "unsupported"):
                bf = QEMU_FORMAT_NAMES.get((d.get("backing_format") or "").lower(), None) if d.get("backing_format") else None
                raw_base = d["format"] == "qcow2" and pkind == "other" and (d.get("backing_format") is None or bf == "raw")
                if raw_base:
                    edge["parent_state"] = "raw or unread"
                    edge["parent_note"] = "the backing file is in the set and is raw or of a kind this tool does not read: present, not examined (a raw base records no identity, and QCOW2 records none of its backing file)"
                else:
                    edge["parent_state"] = ("a sparse extent without a descriptor of its own" if pdisk is not None and pdisk.get("role") == "extent_only" else
                                            "the file is in the set and is not a disk this tool reads" if pdisk is None and pkind in ("other", "vmx", "vmsd", "lock_file") else
                                            "the file is in the set and could not be opened" if pdisk is None and pkind == "unreadable" else
                                            "the file is in the set and was not read (the examination stopped before it)" if pdisk is None else pdisk["state"])
                    if d.get("backing_format") and pkind == "other":
                        edge["format_note"] = "the child says the backing file is %s and the file found is not one this tool reads" % shown(d["backing_format"], fid, "backing format")
                    node_issue[fid].setdefault("parent_unreadable", fid)
            else:
                edge["parent_state"] = pdisk["state"]
                if d["format"] in ("vmdk", "vhd", "vhdx"):
                    want, have = d.get("parent_id"), pdisk.get("own_id")
                    if pdisk["format"] != d["format"]:
                        edge["id_check"] = "not_available"
                        edge["format_note"] = "the parent is a %s file and the child a %s file" % (pdisk["format"], d["format"])
                        node_issue[fid].setdefault("identity_not_compared", fid)
                    elif want and have:
                        if d["format"] == "vhdx":
                            edge["compared"] = "the child's parent_linkage with the parent's DataWriteGuid (MS-VHDX)"
                        if want.upper() == have.upper():
                            edge["id_check"] = "match"
                        elif d["format"] == "vhdx" and d.get("parent_id_2") and d["parent_id_2"].upper() == have.upper():
                            edge["id_check"] = "match_via_parent_linkage2"
                        else:
                            edge["id_check"] = "mismatch"
                            edge["recorded_by_child"] = want
                            edge["carried_by_parent"] = have
                            node_issue[fid].setdefault("identity_mismatch", fid)
                            marker({"vmdk": "parent_cid_mismatch", "vhd": "parent_unique_id_mismatch", "vhdx": "parent_linkage_mismatch"}[d["format"]], [fid, target["id"]],
                                   "the child records parent identity %s and the parent file carries %s" % (want, have),
                                   "the named parent is not the file the child was made against, or the parent was written after the child was made; the "
                                   "chain through this edge cannot be trusted as one history")
                    else:
                        edge["id_note"] = "an identity is missing on one side (the child's record or the parent's own): not compared"
                        node_issue[fid].setdefault("identity_not_compared", fid)
                elif d["format"] == "qcow2":
                    edge["id_check"] = "not_available"
                    edge["id_note"] = "QCOW2 records no identity of its backing file: the name is all the link there is"
                    bf = d.get("backing_format")
                    if bf:
                        theirs = QEMU_FORMAT_NAMES.get(bf.lower())
                        if theirs != pdisk["format"]:
                            edge["format_note"] = "the child says the backing file is %s and the file found is %s" % (shown(bf, fid, "backing format"), pdisk["format"])
            if target is not None:
                parent_of[fid] = target["id"]
            if not target and how == "ambiguous_basename":
                marker("parent_ambiguous", [fid], "the parent's name matches more than one file in the set by file name alone", "which file is the parent is not decided by the set")
            elif not target:
                marker("parent_missing", [fid], "the parent named by the child (%s) is not in the set" % how, "the chain is broken in this set: whether the parent existed, was deleted, "
                                                                                                        "or was not collected is not shown")
            edge_of[fid] = edge
            pages["edges"].add(edge)

        phase = "the extent and CID checks"
        for fid, d in disks.items():
            clock.check(256)
            if d.get("role") == "extent_only" and fid not in extent_targets:
                marker("extent_without_descriptor", [fid], "a sparse extent file is present and no descriptor in the set names it as an extent",
                       "its descriptor was not collected, was removed, or the extent belongs to a disk outside this set: a candidate; the descriptor, if found, holds the chain")
        by_cid = collections.defaultdict(list)
        for fid, d in disks.items():
            if d.get("format") == "vmdk" and d.get("own_id") and d["own_id"] != "ffffffff" and fid not in extent_targets:
                by_cid[d["own_id"]].append(fid)
        for cid, ids in by_cid.items():
            clock.check(256)
            if len(ids) > 1:
                marker("duplicate_cid", ids[:20], "%d descriptors carry the same CID %s" % (len(ids), cid),
                       "a copy of one descriptor, or a clone made without a new CID: a child's parentCID cannot tell these files apart, so an identity match "
                       "through any of them proves less", files_with_this_cid=len(ids))

        # ---- chains: each node's depth, base and first problem toward the base, found once (no recursion) -----------
        phase = "the chain walk"
        for start in disks:
            if start in depth:
                continue
            path_nodes, seen_here, cur = [], set(), start
            while True:
                clock.check(4096)
                if cur in depth:
                    outcome = ("known", cur)
                    break
                if cur in seen_here:
                    outcome = ("cycle", cur)
                    break
                if len(path_nodes) >= max_chain:
                    outcome = ("too_deep", cur)
                    break
                seen_here.add(cur)
                path_nodes.append(cur)
                nxt = parent_of.get(cur)
                if nxt is None:
                    outcome = ("end", cur)
                    break
                cur = nxt
            kind_, at = outcome
            if kind_ == "known":
                b, dp, st, fi, cy = base[at], depth[at], state_of[at], first_issue[at], cycle_of.get(at)
            elif kind_ == "end":
                b, dp, st, fi, cy = path_nodes[-1], 0, None, {}, None
            elif kind_ == "cycle":
                members = path_nodes[path_nodes.index(at):]
                cy = min(members)
                marker("chain_cycle", members[:20], "following parent names from %s returns to %s (%d file(s) on the cycle)" % (at, at, len(members)),
                       "the set contains files that name each other (or themselves) as parents; no history has a cycle, so at least one name or file is wrong",
                       files_on_cycle=len(members))
                for n in members:
                    depth[n], base[n], state_of[n], first_issue[n], cycle_of[n] = len(members), cy, "cycle", node_issue.get(n, {}), cy
                path_nodes = path_nodes[:path_nodes.index(at)]
                b, dp, st, fi = cy, len(members), "cycle", {}
            else:
                b, dp, st, fi, cy = at, 0, "too_deep", {}, None
            for n in reversed(path_nodes):
                dp += 1
                own = node_issue.get(n)
                fi = dict(fi, **own) if own else fi       # the issue nearest the leaf wins; a node with none shares its parent's
                depth[n], base[n], state_of[n], first_issue[n] = dp, b, st or ("too_deep" if dp > max_chain else None), fi
                if cy is not None:
                    cycle_of[n] = cy

        phase = "the chain rows"
        named_as_parent = set(parent_of.values())
        leaves = [f for f in disks if f not in named_as_parent and disks[f].get("role") != "extent_only" and disks[f].get("format") and f not in extent_targets]
        cycles_reached = set()

        def chain_row(leaf, status_override=None):
            ids, cur, seen = [], leaf, set()
            while cur and cur not in seen and len(ids) < MAX_CHAIN_SHOWN:
                ids.append(cur)
                seen.add(cur)
                cur = parent_of.get(cur)
            issues = first_issue.get(leaf, {})
            st = status_override or state_of.get(leaf)
            status, detail = "complete", None
            if st in ("cycle", "too_deep"):
                status = st
                detail = ("the chain from %s runs into a cycle" % leaf) if st == "cycle" else "the chain is deeper than max_chain_depth (%d)" % max_chain
            else:
                for k in CHAIN_ORDER[2:]:
                    if k in issues:
                        status, detail = k, CHAIN_DETAIL[k] % issues[k]
                        break
            row = {"leaf": leaf, "leaf_file": disks[leaf]["file"] if leaf in disks else None, "format": disks.get(leaf, {}).get("format"), "chain_length": depth.get(leaf, 1),
                   "base": base.get(leaf, leaf), "chain_shown": ids, "chain_shown_cut": depth.get(leaf, 1) > len(ids), "status": status, "detail": detail,
                   "issues": {k: issues[k] for k in CHAIN_ORDER if k in issues}}
            b = base.get(leaf, leaf)
            if b not in disks and st not in ("cycle", "too_deep"):
                row["base_note"] = "the base %s is in the set and is not a disk this tool reads (raw, another kind of file, or not opened): present, not examined" % b
            chain_summary[status] += 1
            if status == "too_deep":
                too_deep_leaves.append(leaf)
            pages["chains"].add(row)

        for leaf in leaves:
            clock.check(256)
            if cycle_of.get(leaf) is not None:
                cycles_reached.add(cycle_of[leaf])
            chain_row(leaf)
        for cy in sorted({c for c in cycle_of.values()} - cycles_reached):
            clock.check(256)
            chain_row(cy, "cycle")       # a cycle no leaf reaches (every file on it is named by another) has a row of its own

        # ---- the configuration files held against the descriptors -----------------------------------------------------
        phase = "the configuration files"
        snap_disk_names = {}
        for res in vmsd_list:
            rec = res["rec"]
            data = res["vmsd"]
            for e in data["entries"]:
                clock.check(256)
                names = [shown(n, rec["id"], "snapshot disk file") for n in e["disks"].values()]
                pages["snapshot_database"].add({"source_id": rec["id"], "index": e["index"], "line": e["line"], "uid": shown(e.get("uid"), rec["id"], "snapshot uid"), "parent": shown(e.get("parent"), rec["id"], "snapshot parent"),
                                                "display_name": shown(e.get("displayname"), rec["id"], "snapshot name") if e.get("displayname") is not None else None,
                                                "description_present": "description" in e, "state_file": shown(e.get("filename"), rec["id"], "snapshot state file") if e.get("filename") is not None else None,
                                                "disk_files": names, "create_time_high_raw": shown(e.get("createtimehigh"), rec["id"], "createTimeHigh"), "create_time_low_raw": shown(e.get("createtimelow"), rec["id"], "createTimeLow"),
                                                "create_time_note": "raw values as written; how the two fields encode a time is not decoded here"})
                for n in e["disks"].values():
                    target, how = index.resolve(rec["rel"], n)
                    snap_disk_names.setdefault(rec["id"], set()).add(target["id"] if target else None)
                    if target is None:
                        marker("snapshot_disk_missing", [rec["id"]], "snapshot %s of the database names a disk file that is not in the set (%s)" % (e["index"], how),
                               "the snapshot's disk is missing from this set: removed, never collected or renamed; the database entry alone does not say which", line=e["line"])
            if data["over"]:
                partial.append("a snapshot database lists more than %d snapshot indexes: the first %d are listed, %d more entries were counted and not listed" % (MAX_SNAPSHOT_ENTRIES, MAX_SNAPSHOT_ENTRIES, data["over"]))
        vmsd_by_dir = collections.defaultdict(list)
        for v in vmsd_list:
            if v["state"] == "parsed":               # a database that was not read says nothing about how many snapshots it lists
                vmsd_by_dir[posixpath.dirname(v["rec"]["rel"])].append(v)
        for res in vmx_list:
            rec = res["rec"]
            for dk in res["vmx"]["disks"]:
                clock.check(256)
                target, how = index.resolve(rec["rel"], dk["file"])
                d = disks.get(target["id"]) if target else None
                if d and d.get("has_parent"):
                    for v in vmsd_by_dir.get(posixpath.dirname(rec["rel"]), ()):
                        clock.check(256)
                        n = len(v["vmsd"]["entries"])
                        declared = v["vmsd"]["top"].get("numsnapshots")
                        if n == 0 or declared in ("0", 0):
                            marker("running_disk_is_a_delta_without_snapshots", [rec["id"], target["id"], v["rec"]["id"]],
                                   "the configuration's disk %s is a delta (it records a parent) and the snapshot database lists %s snapshot(s)" % (
                                       shown(dk["key"], rec["id"], "disk key"), shown(declared, v["rec"]["id"], "numSnapshots") if declared is not None else n),
                                   "a consolidation that did not finish, a snapshot removed without its delta merged, or a database that was not collected with the disk: a "
                                   "candidate; the VM's task log decides it", line=dk["line"])
        if vmsd_list:
            referenced = set()
            for ids in snap_disk_names.values():
                referenced.update(i for i in ids if i)
            for res in vmx_list:
                for dk in res["vmx"]["disks"]:
                    clock.check(256)
                    target, _how = index.resolve(res["rec"]["rel"], dk["file"])
                    if target:
                        referenced.add(target["id"])
            reachable, stack = set(), list(referenced)
            while stack:                          # the ancestors of every disk the configuration names are in use
                clock.check(4096)
                cur = stack.pop()
                if cur in reachable:
                    continue
                reachable.add(cur)
                if cur in parent_of:
                    stack.append(parent_of[cur])
            listing = [v["rec"]["id"] for v in vmsd_list][:20]
            for fid, d in disks.items():
                clock.check(256)
                if d.get("format") == "vmdk" and d.get("has_parent") and fid not in reachable and fid not in extent_targets:
                    marker("delta_not_in_snapshot_database", [fid] + listing,
                           "this descriptor records a parent, and it is neither named by the snapshot database or the configuration nor a parent of a disk they name",
                           "a delta left behind by a removed snapshot or a consolidation, or a file of another VM in the set: a candidate; the task log decides it")
        for rel in files.lock_dirs:
            marker("lock_artefact", [], "an entry named %s is present" % shown(rel, "walk", "lock directory"),
                   "a lock directory or file is made while a program holds the disk or the VM; it can be a copy of a live VM's directory or a left-over after a crash: a candidate")
    except Overtime:
        partial.append("%s was reached during %s: the rows after the last one listed were not made, and the chain rows, edges and markers "
                       "listed are the ones made before it" % (at_limit, phase))

    # ---- qemu-img, when asked ------------------------------------------------------------------------------------------
    qemu_report = {"mode": qemu_mode, "checked": 0, "available": None, "note": "qemu-img was not run (qemu_img: off); the reading above is the tool's own"}
    if qemu_mode != "off":
        qemu_report["note"] = ("qemu-img info was run once per image of the set with the format fixed and without --backing-chain; its answer sits beside the "
                               "native reading in `qemu_img` of the disk row and replaces nothing. A VMDK text descriptor and a QCOW2 image with an external "
                               "data file are not given to it (qemu-img would open the files they name, which can lie outside the set), nor an extent "
                               "another descriptor names (the disk is that descriptor)")
        cross, failed_runs = [], []
        skipped = collections.Counter()
        skipped_first = {}
        count = 0
        for fid, d in disks.items():
            fmt_kind = {"vmdk": "vmdk", "vhd": "vhd", "vhdx": "vhdx", "qcow2": "qcow2"}.get(d.get("format"))
            if not fmt_kind or d.get("role") == "extent_only" or d["state"] != "parsed":
                continue
            why = None
            if d["format"] == "vmdk" and nodes[fid]["row"]["kind"] != "vmdk_sparse":
                why = "text_descriptor"           # qemu-img would open its extents by the names it holds
            elif fid in extent_targets:
                why = "extent_of_another_descriptor"   # a split disk's extent: the disk is its descriptor, which qemu-img is not given
            elif d.get("external_data_file"):
                why = "external_data_file"        # qemu-img would open the data file by the name the header holds
            elif count >= qemu_max:
                why = "over_qemu_img_max_images"
            elif out_clock.left() < 2.5:
                why = "max_seconds"
            if why:
                skipped[why] += 1
                skipped_first.setdefault(why, fid)
                continue
            rec = nodes[fid]["rec"]
            result = run_qemu(rec["path"], fmt_kind, min(30.0, max(1.0, out_clock.left() - 1.5)))
            count += 1
            qemu_report["available"] = result.get("available")
            if result.get("available") is False:
                break
            d["qemu_img"] = result
            if result.get("timed_out") or result.get("exit_code") != 0 or result.get("error"):
                failed_runs.append(fid)
                continue
            native = d.get("detail") or {}
            if d["format"] == "vmdk":
                cap = (native.get("sparse_header") or {}).get("capacity_sectors")
                native_size = (cap if cap is not None else native.get("capacity_sectors_by_extents"))
                native_size = native_size * 512 if native_size is not None else None
            else:
                native_size = native.get("virtual_size") if d["format"] in ("qcow2", "vhdx") else native.get("current_size") if d["format"] == "vhd" else None
            if result.get("virtual_size") is not None and native_size is not None and result["virtual_size"] != native_size:
                marker("qemu_img_disagrees", [fid], "qemu-img reports virtual size %s and the header reads %s" % (result["virtual_size"], native_size),
                       "one of the two readings is wrong or the file is damaged; neither is preferred")
            cross.append(fid)
        qemu_report["checked"] = len(cross)
        qemu_report["failed"] = len(failed_runs)
        qemu_report["failed_first"] = failed_runs[:20]
        qemu_report["skipped"] = dict(skipped)
        qemu_report["skipped_first"] = skipped_first
        if qemu_mode == "require" and qemu_report["available"] is False:
            fail("qemu_img: require was asked for and qemu-img is not on PATH (the base pack lists it as optional: check the image the job runs in)")
        if qemu_report["available"] is False:
            qemu_report["note"] = "qemu-img is not on PATH here (the base pack lists it as optional): the native reading above is all there is"
        else:
            if failed_runs:
                partial.append("qemu-img failed, timed out or printed no JSON on %d image(s) (first %s): the second reading of those is missing" % (len(failed_runs), failed_runs[0]))
            for why in ("over_qemu_img_max_images", "max_seconds"):
                if skipped.get(why):
                    partial.append("qemu-img was not run on %d eligible image(s) (%s; first %s)" % (skipped[why], "qemu_img_max_images (%d) was reached" % qemu_max if why != "max_seconds" else "max_seconds was near", skipped_first[why]))
            if qemu_report["checked"] == 0 and not failed_runs:
                qemu_report["note"] += "; no parsed image was eligible"

    # ---- disks page ------------------------------------------------------------------------------------------------
    listed = 0
    for fid, d in disks.items():
        try:
            out_clock.check(256)
        except Overtime:
            partial.append("max_seconds (%s) was reached while the disk rows were written: %d of %d are listed (the edges and chains name the rest by id)" % (seconds, listed, len(disks)))
            break
        listed += 1
        row = {"source_id": fid, "file": d["file"], "format": d.get("format"), "state": d["state"], "role": d.get("role", "disk"),
               "own_id": d.get("own_id"), "records_a_parent": bool(d.get("has_parent")), "is_extent_of": extent_targets.get(fid),
               "depth": depth.get(fid), "base": base.get(fid), "chain_state": state_of.get(fid), "detail": make_net(shown, fid)(d.get("detail"))}
        if d.get("format") == "vhdx":
            row["own_id_field"] = "DataWriteGuid of the current header (what a child's parent_linkage records)"
        if d.get("qemu_img"):
            row["qemu_img"] = d["qemu_img"]
        pages["disks"].add(row)

    if damaged:
        partial.append("%d header(s) failed their checksum (first %s: %s): read as written and named in markers; what they record may be wrong" % (len(damaged), damaged[0][0], damaged[0][1]))
    if too_deep_leaves:
        partial.append("max_chain_depth (%d) was reached on %d chain(s) (first leaf %s): those chains were not followed to their base" % (max_chain, len(too_deep_leaves), too_deep_leaves[0]))
    if extents_over:
        partial.append("%d descriptor(s) list more than %d extents (first %s): the first %d of each were checked and the rest are counted in extents_total" % (len(extents_over), MAX_EXTENTS, extents_over[0], MAX_EXTENTS))
    if config_total["dropped"]:
        partial.append("the .vmx and .vmsd files hold more than %d entries between them: %d file(s) were counted and their entries were not held against the descriptors" % (MAX_CONFIG_ENTRIES_TOTAL, config_total["dropped"]))
    values.close()
    result_pages = {k: v.finish() for k, v in pages.items()}
    all_parsed = not problems
    complete = all_parsed and not partial and not files.skipped_counts["unreadable"] and not files.skipped_counts["too_deep"]
    outcome = status_of(complete, bool(files.files) and examined == 0 and bool(problems),
                        "every recognised file in the set was read, none was left out, and every limit held",
                        "%d recognised file(s) were not read whole (failed, unsupported or partial), %d unreadable, %d directory(ies) too deep%s: the answer names them" % (
                            len(problems), files.skipped_counts["unreadable"], files.skipped_counts["too_deep"], ("; " + "; ".join(partial)) if partial else ""),
                        "no recognised file could be read")
    recognised = sum(c for k, c in kinds.items() if k != "other")
    if files.files and not recognised and outcome["status"] == "complete":
        outcome = {"status": "complete", "status_basis": "the set holds no file of a kind this tool reads (%d other file(s), counted by extension): zero disks is a statement about this tool's formats, not about the VM" % sum(other_ext.values())}
    if not files.files:
        skipped = sum(files.skipped_counts.values())
        outcome = ({"status": "partial", "status_basis": "the set holds no file that could be read; %d entr(ies) were skipped (links, special files, directories too deep, unreadable)%s: the answer names them" % (skipped, ("; " + "; ".join(partial)) if partial else "")}
                   if skipped or partial else {"status": "failed", "status_basis": "the set holds no file"})
    print(answer_text({
        "parser": PARSER, **outcome,
        "root": files.root_shown, "files_in_set": len(files.files), "kinds": dict(kinds), "other_files_by_extension": dict(other_ext.most_common(20)),
        "other_files_note": "files of no kind this tool reads are counted by extension and not examined (an extension that is not 1 to 10 letters or digits is counted under (other extensions) and not shown); absence of a disk here is not absence of a disk",
        "states": dict(state_counts), "recognised_not_read_whole": problems[:200],
        "sources": pages["sources"].page, "disks": pages["disks"].page, "edges": pages["edges"].page, "chains": pages["chains"].page,
        "extents": pages["extents"].page, "snapshot_database": pages["snapshot_database"].page, "internal_snapshots": pages["internal_snapshots"].page,
        "markers": pages["markers"].page, "pages": result_pages,
        "chain_summary": dict(chain_summary),
        "chain_note": ("A chain is complete when every parent a disk names is in the set, can be read, and carries the identity the child recorded where the format "
                       "records one, and every extent and data file its disks name is in the set. Otherwise its status names the first problem from the leaf "
                       "(cycle, too_deep, broken, parent_unreadable, identity_mismatch, extent_missing, data_file_missing) and `issues` lists each kind found. "
                       "It is not a disk that boots, and it says nothing about the parent's content when the child was made. A QCOW2 child that declares its backing "
                       "format as qcow2 over a file that is raw (or any file this tool does not read as a disk) is `parent_unreadable`: the file found is not the format the child "
                       "declares, and no identity of it is compared."),
        "walk": files.skipped_summary(), "walk_truncated": files.truncated, "partial_reasons": partial, "lock_directories_total": files.lock_dirs_total,
        "qemu_img": qemu_report,
        "text": values.summary(), "withheld": withheld_summary(shown),
        "truncated": any(p["truncated"] for p in result_pages.values()),
        "limits": {"max_files": max_files, "max_entries": max_entries, "max_depth": max_depth, "max_snapshots": max_snapshots, "max_chain_depth": max_chain, "descriptor_read_cap": MAX_DESCRIPTOR},
        "note": "Markers are candidates with the observation beside them. A header or a descriptor says what its writer recorded; it does not say who or what wrote it, when, or why. "
                "Corroborate with the hypervisor's own task and event records before calling a snapshot deleted, a consolidation failed or a disk tampered with.",
    }))
    return 0 if outcome["status"] != "failed" else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except SystemExit:
        raise
    except BaseException as exc:  # noqa: BLE001 - never a traceback, never a clean answer for a failure
        fail("unexpected failure: %s" % describe(exc))
