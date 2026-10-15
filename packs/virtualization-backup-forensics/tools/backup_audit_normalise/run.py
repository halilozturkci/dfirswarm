#!/usr/bin/env python3
"""Normalise a backup or hypervisor job record into canonical events, one source line or record at a time, and say what
was not understood.

The products and layouts read, and no others:

    Proxmox VE and Proxmox Backup Server   the task index (UPID lines: node, pid, start, type, id, user, then the end time
                                           and status; a Backup Server UPID carries one more field, the task counter, and
                                           escapes its worker id) and a Proxmox VE task log (vzdump log lines and the
                                           TASK result line; a Backup Server task log is not read)
    declared_csv, declared_jsonl,          an export of ANY product, read through a mapping the CALLER declares (which
    declared_xml                           column or field is the time, the action, the result, the actor and the object, how
                                           the time is written, and what each action means). The tool does not know the
                                           product: it reads the columns you name and says so on every event.

A product that is none of these is `unsupported` until fixtures for its format exist: this tool does not guess a vendor's
layout from a name or a sample. Name the format (`format`) or let `auto` recognise the Proxmox layouts only; asking for
another product by name is refused, with the declared route offered.

What an event is. It is what a line or record says happened, with where it was read (file, line or record, byte offset) and
how its time was read. It is not proof the operation took place as described, that it succeeded because a record says so, or
who did it: an actor field is the account the product wrote. A category is a label from this tool's table (or the caller's
category_map) for the action's name; the raw action stays beside it. A job record that says success is not a restore that
worked; a delete request is not a loss (see the skills).

Time is read exactly as declared: epoch seconds are UTC by definition; an ISO 8601 time with an offset is converted; a time
with no zone is NOT assumed UTC, it stays raw (`time_utc` is null and `time_basis` says why) unless the caller declares a fixed
offset, which does not account for daylight saving.

A declared field a record does not have is counted per field (the CSV header check's twin for JSON Lines and XML), and a
time or action absent makes the answer partial. A declared XML record is held in memory one at a time and is bounded in
bytes: a record over the budget is counted and located, never read in part.

SENSITIVE OUTPUT. A log message, an error text and an object path can hold a path, a user name, a token or a repository string
with user-info. The answer carries the structured fields after the shape check of the shared block (a token-shaped run or
user-info is withheld; a long text is shown cut with its whole length) and the length of the free-text message; the message
itself and the original of anything withheld go to one private file only when write_text is asked for, in a job. Every key
and value of the answer and of its paging files passes the one way out (SHARED BOUNDARY), which withholds by shape again and
checks what it wrote; a time basis is a fixed phrase, never an exception's text.
"""
import collections
import csv
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
import sys
import tempfile
import time
import unicodedata
from pathlib import Path

TOOL = "backup_audit_normalise"
PARSER = "backup_audit_normalise/1"
DEFAULT_LIMIT = 200
DEFAULT_SECONDS = 50.0          # the manifest allows 60
MAX_SECONDS = 50.0
MAX_LINE = 1 << 20
MAX_FIELD = 1 << 20
MAX_DISTINCT = 10000
MAX_XML_RECORD_ELEMENTS = 10000
MAX_XML_RECORD_BYTES = 4 << 20   # text and attributes one declared XML record may hold; a record over it is counted, not read
MAX_XML_TOKEN = 16 << 20         # bytes the XML reader may take in without one element or text callback (a giant tag or comment)
MAX_XML_DEPTH = 64
MAX_PATHS = 100
CATEGORIES = ("backup_job", "backup_start", "backup_end", "backup_error", "archive_created", "restore", "snapshot_create", "snapshot_delete",
              "snapshot_rollback", "retention_prune", "retention_gc", "retention_remove", "verification", "sync", "vm_create", "vm_delete",
              "vm_power", "vm_start", "clone", "migrate", "disk_delete", "config_change", "repository_change", "login", "task_end", "other")
RESULTS = ("ok", "warning", "error", "unknown")
PVE_TYPES = {"vzdump": "backup_job", "backup": "backup_job", "qmsnapshot": "snapshot_create", "vzsnapshot": "snapshot_create",
             "qmdelsnapshot": "snapshot_delete", "vzdelsnapshot": "snapshot_delete", "qmrollback": "snapshot_rollback", "vzrollback": "snapshot_rollback",
             "qmdestroy": "vm_delete", "vzdestroy": "vm_delete", "qmrestore": "restore", "vzrestore": "restore", "reader": "restore", "imgdel": "disk_delete",
             "qmstart": "vm_start", "vzstart": "vm_start", "qmstop": "vm_power", "vzstop": "vm_power", "qmshutdown": "vm_power", "vzshutdown": "vm_power",
             "qmreboot": "vm_power", "qmreset": "vm_power", "qmclone": "clone", "qmigrate": "migrate", "vzmigrate": "migrate", "qmcreate": "vm_create",
             "vzcreate": "vm_create", "prune": "retention_prune", "prunejob": "retention_prune", "garbage_collection": "retention_gc", "verify": "verification",
             "verificationjob": "verification", "syncjob": "sync", "sync": "sync"}
KNOWN_UNSUPPORTED = ("veeam", "commvault", "rubrik", "cohesity", "acronis", "veritas", "netbackup", "networker", "nakivo", "altaro", "hycu", "druva",
                     "backup_exec", "arcserve", "vcenter", "vsphere", "hyper-v", "hyperv", "nutanix", "ovirt", "xen", "azure_backup", "aws_backup")

VOCABULARY = frozenset()     # words the way out shows as they are (see SHARED BOUNDARY): none here

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


def iso_from_epoch(value):
    try:
        stamp = datetime.datetime(1970, 1, 1, tzinfo=datetime.timezone.utc) + datetime.timedelta(seconds=value)
        return stamp.strftime("%Y-%m-%dT%H:%M:%S") + (".%06d" % stamp.microsecond if stamp.microsecond else "") + "Z"
    except (OverflowError, ValueError, OSError):
        return None


ISO = re.compile(r"^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2})(?:[.,](\d{1,9}))?\s*(Z|[+-]\d{2}:?\d{2})?$")


class TimeReader:
    """Reads a time exactly as the caller declared it, or says why it could not."""

    def __init__(self, fmt, offset_minutes):
        self.fmt, self.offset = fmt, offset_minutes

    def read(self, raw):
        """(utc iso or None, basis)"""
        if raw is None or (isinstance(raw, str) and not raw.strip()):
            return None, "no time in the record"
        text = raw.strip() if isinstance(raw, str) else raw
        try:
            if self.fmt in ("epoch_seconds", "epoch_milliseconds"):
                value = float(text)
                if not math.isfinite(value) or value < 0:
                    return None, "not a usable epoch value"
                if self.fmt == "epoch_milliseconds":
                    value /= 1000.0
                if value > 253402300799:
                    return None, "epoch value out of range"
                return iso_from_epoch(value), "epoch %s, which are UTC by definition" % self.fmt.split("_")[1]
            if self.fmt == "iso8601":
                m = ISO.match(str(text))
                if not m:
                    return None, "not an ISO 8601 date and time"
                y, mo, d, h, mi, s, frac, zone = m.groups()
                if zone:
                    sign = -1 if zone.startswith("-") else 1
                    digits = zone.lstrip("Z+-").replace(":", "")
                    off = datetime.timedelta(hours=int(digits[:2] or 0), minutes=int(digits[2:] or 0)) * sign
                    basis = "the offset written in the value"
                elif self.offset is not None:
                    off = datetime.timedelta(minutes=self.offset)
                    basis = "a fixed offset of %d minutes declared by the caller; daylight saving is not accounted for" % self.offset
                else:
                    return None, "no zone in the value and none declared: naive local time, not assumed to be UTC"
                local = datetime.datetime(int(y), int(mo), int(d), int(h), int(mi), int(s), tzinfo=datetime.timezone(off))
                utc = local.astimezone(datetime.timezone.utc)
                return utc.strftime("%Y-%m-%dT%H:%M:%S") + ("." + frac if frac else "") + "Z", basis
            if self.fmt.startswith("strptime:"):
                try:
                    parsed = datetime.datetime.strptime(str(text), self.fmt[9:])
                except ValueError:
                    return None, "the value does not match the declared format (strptime)"
                if parsed.tzinfo is not None:
                    return parsed.astimezone(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"), "the zone written in the value (%z)"
                if self.offset is not None:
                    local = parsed.replace(tzinfo=datetime.timezone(datetime.timedelta(minutes=self.offset)))
                    return local.astimezone(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"), "a fixed offset of %d minutes declared by the caller; daylight saving is not accounted for" % self.offset
                return None, "no zone in the value and none declared: naive local time, not assumed to be UTC"
        except (ValueError, OverflowError, OSError, TypeError):
            # a fixed phrase: the exception's text quotes the value, and a basis is a dictionary key of the answer too
            return None, "the value does not match the declared format (not a number, or a date or time out of range)"
        return None, "unknown time format"


class Events:
    """The canonical events: counted, paged whole, and aggregated within a bound."""

    def __init__(self, limit, shown, text):
        self.page = LosslessPage(TOOL, "events", limit)
        self.shown, self.text = shown, text
        self.n = 0
        self.by_category = collections.Counter()
        self.by_result = collections.Counter()
        self.first = self.last = None
        self.time_derived = self.time_not_derived = 0
        self.distinct = {"object": collections.Counter(), "actor": collections.Counter(), "host": collections.Counter()}
        self.distinct_over = collections.Counter()
        self.time_reasons = collections.Counter()

    def add(self, source, locator, fmt, **f):
        self.n += 1
        fid = source["id"]
        category = f.get("category", "other")
        result = f.get("result", "unknown")
        self.by_category[category] += 1
        self.by_result[result] += 1
        t = f.get("time_utc")
        if t:
            self.time_derived += 1
            self.first = t if self.first is None or t < self.first else self.first
            self.last = t if self.last is None or t > self.last else self.last
        else:
            self.time_not_derived += 1
            self.time_reasons[f.get("time_basis") or ""] += 1
        row = {"seq": self.n, "source_id": fid, "format": fmt, "locator": locator}
        for key in ("object", "actor", "host"):
            if f.get(key) is not None:
                f[key] = self.shown(f[key], "%s#%d" % (fid, self.n), key)
                counter = self.distinct[key]
                if f[key] in counter or len(counter) < MAX_DISTINCT:
                    counter[f[key]] += 1
                else:
                    self.distinct_over[key] += 1
        for key in ("action_raw", "result_raw", "category_raw", "job", "time_raw", "end_time_raw"):
            if f.get(key) is not None:
                f[key] = self.shown(f[key], "%s#%d" % (fid, self.n), key)
        message = f.pop("message", None)
        if message is not None:
            f["message_chars"] = len(message)
            if self.text.enabled:
                self.text.add({"record_type": "message", "seq": self.n, "source_id": fid, "locator": locator, "message": message})
        row.update(f)
        self.page.add(row)


def read_lines(fh, max_line):
    """(number, offset, length, bytes or None for an over-long line) a line at a time, never holding more than max_line + 1 bytes."""
    n, offset = 0, 0
    while True:
        raw = fh.readline(max_line + 1)
        if not raw:
            return
        n += 1
        start, length = offset, len(raw)
        if len(raw) > max_line and not raw.endswith(b"\n"):
            while True:
                more = fh.readline(max_line)
                length += len(more)
                if not more or more.endswith(b"\n"):
                    break
            offset += length
            yield n, start, length, None
            continue
        offset += length
        yield n, start, length, raw


def decode_line(raw):
    body = raw[:-1] if raw.endswith(b"\n") else raw
    if body.endswith(b"\r"):
        body = body[:-1]
    return body.decode("utf-8", "surrogateescape")


# ---- Proxmox ---------------------------------------------------------------------------------------------------------

# Proxmox VE: UPID:node:pid:pstart:starttime:type:id:user:   (pid, starttime 8 hexadecimal digits; pstart 8 or more)
# Proxmox Backup Server: UPID:node:pid:pstart:task_id:starttime:worker_type:worker_id:auth_id:   (one more field, the task
# counter; the worker id is escaped as a systemd unit name, \xNN, `-` for `/`). Either is followed, in the task index, by
# the end time (8 hexadecimal digits) and the status when the task ended.
UPID = re.compile(r"^UPID:([^:]*):([0-9A-Fa-f]{8}):([0-9A-Fa-f]{8,16}):([0-9A-Fa-f]{8}):([^:]*):([^:]*):([^:]*):(?:\s+([0-9A-Fa-f]{8})\s*(.*))?$")
UPID_PBS = re.compile(r"^UPID:([^:]*):([0-9A-Fa-f]{8}):([0-9A-Fa-f]{8,16}):([0-9A-Fa-f]{8}):([0-9A-Fa-f]{8}):([^:]*):([^:]*):([^:]*):(?:\s+([0-9A-Fa-f]{8})\s*(.*))?$")


def systemd_unescape(text):
    """A PBS worker id as written (systemd unit-name escaping: `-` stands for `/`, \\xNN for a byte) back to its text."""
    out, i = [], 0
    while i < len(text):
        if text.startswith("\\x", i) and re.fullmatch(r"[0-9a-fA-F]{2}", text[i + 2:i + 4]):
            out.append(chr(int(text[i + 2:i + 4], 16)))
            i += 4
        else:
            out.append("/" if text[i] == "-" else text[i])
            i += 1
    return "".join(out)


def pve_category(task_type):
    t = (task_type or "").lower()
    if t in PVE_TYPES:
        return PVE_TYPES[t], "worker type table of this tool"
    for needle, cat in (("prune", "retention_prune"), ("garbage", "retention_gc"), ("verif", "verification"), ("delsnap", "snapshot_delete")):
        if needle in t:
            return cat, "keyword '%s' in the worker type (this tool's table; check the product version)" % needle
    return "other", "the worker type is not in this tool's table"


def parse_task_index(fh, source, events, clock, max_line, stats):
    for n, off, length, raw in read_lines(fh, max_line):
        clock.check(1024)
        if raw is None:
            stats["over_limit"] += 1
            stats["problem_lines"].append({"source_id": source["id"], "line": n, "byte_offset": off, "reason": "line over max_line_bytes: located, not read"})
            continue
        line = decode_line(raw)
        if not line.strip():
            stats["blank"] += 1
            continue
        m = UPID_PBS.match(line.strip())
        product = "proxmox_backup_server"
        if m:
            node, pid, pstart, task_no, starttime, ttype, wid, user, endtime, status = m.groups()
            tid = systemd_unescape(wid) if wid else wid
        else:
            m = UPID.match(line.strip())
            product, task_no, wid = "proxmox_ve", None, None
            if m:
                node, pid, pstart, starttime, ttype, tid, user, endtime, status = m.groups()
        if not m:
            stats["unparsed"] += 1
            if len(stats["problem_lines"]) < 200:
                stats["problem_lines"].append({"source_id": source["id"], "line": n, "byte_offset": off, "reason": "not a UPID task line"})
            continue
        start_utc = iso_from_epoch(int(starttime, 16))
        end_utc = iso_from_epoch(int(endtime, 16)) if endtime else None
        status = (status or "").strip()
        category, basis = pve_category(ttype)
        if endtime is None:
            result, result_basis = "unknown", "no end time or status on the line: the task was running, interrupted or not yet indexed"
        elif status == "OK":
            result, result_basis = "ok", "status OK"
        elif status.upper().startswith("WARNINGS"):
            result, result_basis = "warning", "status begins WARNINGS"
        elif status.lower() == "unknown":
            # the product wrote that it does not know how the task ended (a task whose worker went away); not an error
            result, result_basis = "unknown", "status unknown: the product did not derive how the task ended (this tool's mapping of that word)"
        else:
            result, result_basis = "error", "status other than OK, WARNINGS or unknown (this tool's mapping)"
        stats["parsed"] += 1
        task = {"pid": int(pid, 16), "pstart": pstart, "upid_layout": product}
        if product == "proxmox_backup_server":
            # Each form shows what the other holds (\x41 is A; unescaping turns `-` into `/`, which can split a token the
            # written form holds whole): when either is withheld, both are.
            as_written = None
            if wid:
                where = "%s#%d" % (source["id"], events.n + 1)
                obj_shown, wid_shown = events.shown(tid, where, "worker id"), events.shown(wid, where, "worker id as written")
                if obj_shown == tid and wid_shown == wid:
                    as_written = wid
                else:
                    as_written = "<withheld: %d bytes, field worker id>" % blen(wid)        # one form is withheld, so both are
                    tid = "<withheld: %d bytes, field worker id>" % blen(tid)
            task.update(task_counter=int(task_no, 16), worker_id_as_written=as_written,
                        worker_id_note="Proxmox Backup Server writes the worker id escaped as a systemd unit name; object is it unescaped")
        events.add(source, {"line": n, "byte_offset": off, "byte_length": length}, "pve_task_index", time_utc=start_utc, time_raw=starttime, time_basis="start time, epoch seconds in hexadecimal, UTC by definition",
                   end_time_utc=end_utc, end_time_raw=endtime, category=category, category_basis=basis, action_raw=ttype, object=tid or None, actor=user or None, host=node or None,
                   result=result, result_basis=result_basis, result_raw=status or None, task=task)


LOG_PREFIX = re.compile(r"^(INFO|WARN|ERROR|TASK OK|TASK ERROR|TASK WARNINGS)(?::\s?|$)(.*)$")
LOG_PATTERNS = [
    (re.compile(r"^starting new backup job: vzdump(.*)$"), "backup_job", "unknown", "job start", "starting new backup job"),
    (re.compile(r"^Starting Backup of VM (\d+) \((\w+)\)$"), "backup_start", "unknown", "backup of one guest started", "Starting Backup of VM"),
    (re.compile(r"^Finished Backup of VM (\d+) \(([\d:]+)\)$"), "backup_end", "ok", "backup of one guest finished", "Finished Backup of VM"),
    (re.compile(r"^Backup of VM (\d+) failed - (.*)$"), "backup_error", "error", "backup of one guest failed", "Backup of VM failed"),
    (re.compile(r"^creating (?:vzdump|pbs) archive '(.*)'$"), "archive_created", "unknown", "an archive was started", "creating archive"),
    (re.compile(r"^Backup job finished successfully$"), "task_end", "ok", "the job's own closing line", "Backup job finished successfully"),
    (re.compile(r"^Backup job finished with errors$"), "task_end", "error", "the job's own closing line", "Backup job finished with errors"),
    (re.compile(r"^removing backup '(.*)'$"), "retention_remove", "unknown", "an older backup was removed (the retention setting's step)", "removing backup"),
    (re.compile(r"^(?:prune|pruned) .*$"), "retention_prune", "unknown", "a prune step", "prune"),
]
LOG_TIME = re.compile(r"^Backup (started|finished) at (\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})$")


def parse_vzdump_log(fh, source, events, clock, max_line, stats, times):
    for n, off, length, raw in read_lines(fh, max_line):
        clock.check(1024)
        if raw is None:
            stats["over_limit"] += 1
            stats["problem_lines"].append({"source_id": source["id"], "line": n, "byte_offset": off, "reason": "line over max_line_bytes: located, not read"})
            continue
        line = decode_line(raw)
        if not line.strip():
            stats["blank"] += 1
            continue
        m = LOG_PREFIX.match(line)
        if not m:
            stats["unparsed"] += 1
            if len(stats["problem_lines"]) < 200:
                stats["problem_lines"].append({"source_id": source["id"], "line": n, "byte_offset": off, "reason": "no INFO, WARN, ERROR or TASK prefix"})
            continue
        level, rest = m.group(1), m.group(2).strip()
        loc = {"line": n, "byte_offset": off, "byte_length": length}
        if level.startswith("TASK"):
            result = {"TASK OK": "ok", "TASK ERROR": "error", "TASK WARNINGS": "warning"}[level]
            stats["parsed"] += 1
            events.add(source, loc, "pve_task_log", time_utc=None, time_raw=None, time_basis="the line carries no time", category="task_end", category_basis="the TASK result line of a task log",
                       action_raw=level, result=result, result_basis="the task's own result line", message=rest)
            continue
        tm = LOG_TIME.match(rest)
        if tm:
            utc, basis = times.read(tm.group(2))
            stats["parsed"] += 1
            events.add(source, loc, "pve_task_log", time_utc=utc, time_raw=tm.group(2), time_basis=basis + " (a node-local time as the log prints it)", category="backup_start" if tm.group(1) == "started" else "backup_end",
                       category_basis="'Backup %s at' line" % tm.group(1), action_raw="Backup %s at" % tm.group(1), result="unknown", result_basis="a time line states no result", message=rest)
            continue
        for pattern, category, result, why, label in LOG_PATTERNS:
            pm = pattern.match(rest)
            if not pm:
                continue
            stats["parsed"] += 1
            groups = pm.groups()
            obj = groups[0] if category in ("backup_start", "backup_end", "backup_error", "archive_created", "retention_remove") else None
            events.add(source, loc, "pve_task_log", time_utc=None, time_raw=None, time_basis="the line carries no time", category=category, category_basis=why, action_raw=label,
                       object=obj, result=result if level != "ERROR" else "error", result_basis=("the level of the line (%s)" % level) if level != "INFO" else "the pattern's meaning, not a confirmed outcome",
                       message=rest)
            break
        else:
            stats["unparsed"] += 1
            if len(stats["problem_lines"]) < 200:
                stats["problem_lines"].append({"source_id": source["id"], "line": n, "byte_offset": off, "reason": "a %s line this tool has no pattern for" % level})
            if level in ("WARN", "ERROR"):
                stats["parsed"] += 1
                stats["unparsed"] -= 1
                if stats["problem_lines"] and stats["problem_lines"][-1]["line"] == n and stats["problem_lines"][-1]["source_id"] == source["id"]:
                    stats["problem_lines"].pop()
                events.add(source, loc, "pve_task_log", time_utc=None, time_raw=None, time_basis="the line carries no time", category="other", category_basis="a WARN or ERROR line this tool has no pattern for",
                           action_raw=level, result="warning" if level == "WARN" else "error", result_basis="the level of the line", message=rest)


# ---- declared mappings -----------------------------------------------------------------------------------------------

MISSING = object()   # a declared field the record does not have (a field that is there and null or empty is not missing)


def get_path(obj, path):
    """A value of a nested JSON object by dotted path; MISSING when the path is not in the object."""
    cur = obj
    for part in path.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return MISSING
    return cur


def scalar(value):
    if value is None:
        return None
    if isinstance(value, (dict, list)):
        return json.dumps(value)[:MAX_FIELD]
    return str(value)


def declared_event(events, source, loc, fmt, record_get, mapping, times, category_map, result_map, stats):
    stats["records_declared"] += 1

    def field(name):
        """The declared field's value; a field the record does not have is counted per field (the CSV header check's twin)."""
        if not mapping.get(name):
            return None
        value = record_get(mapping[name])
        if value is MISSING:
            stats["fields_absent"][name] += 1
            return None
        return scalar(value)
    raw_time = field("time")
    utc, basis = times.read(raw_time)
    action = field("action")
    result_raw = field("result")
    if action is not None and action.lower() in category_map:
        category, category_basis = category_map[action.lower()], "declared in category_map"
    else:
        category, category_basis = "other", "not in the caller's category_map" if category_map else "no category_map declared: the action is kept raw"
        if action is not None:
            key = events.shown(action, "actions", "action")      # withheld by shape whole, then cut: never cut first
            if key in stats["unmapped_actions"] or len(stats["unmapped_actions"]) < 500:
                stats["unmapped_actions"][key] += 1
            else:
                stats["unmapped_actions_over"] += 1
    if result_raw is not None and result_raw.lower() in result_map:
        result, result_basis = result_map[result_raw.lower()], "declared in result_map"
    else:
        result, result_basis = "unknown", ("not in the caller's result_map" if result_map else "no result_map declared") if result_raw is not None else "no result field in the record"
    events.add(source, loc, fmt, time_utc=utc, time_raw=raw_time, time_basis=basis, category=category, category_basis=category_basis, action_raw=action,
               object=field("object"), actor=field("actor"), host=field("host"), job=field("job"),
               result=result, result_basis=result_basis, result_raw=result_raw, message=field("message"),
               mapping_declared_by="the caller; the tool does not know the product")
    stats["parsed"] += 1


def parse_csv(fh, source, events, clock, max_line, stats, mapping, times, category_map, result_map, delimiter, has_header, columns):
    csv.field_size_limit(MAX_FIELD)
    text = (l.decode("utf-8", "surrogateescape") for l in iter(lambda: fh.readline(max_line + 1), b""))
    reader = csv.reader(text, delimiter=delimiter)
    header, record = columns, 0
    used = {v for v in mapping.values() if isinstance(v, str)}
    try:
        for row in reader:
            clock.check(1024)
            if header is None and has_header:
                header = [c.strip().lstrip("﻿") for c in row]
                missing = sorted(u for u in used if u not in header)
                if missing:
                    stats["mapping_errors"].append("the declared column(s) %s are not in the header (%d columns)" % (", ".join(shown_names(missing)), len(header)))
                    return
                continue
            if header is None:
                header = columns
            record += 1
            if not row:
                stats["blank"] += 1
                continue
            if len(row) != len(header):
                stats["unparsed"] += 1
                if len(stats["problem_lines"]) < 200:
                    stats["problem_lines"].append({"source_id": source["id"], "record": record, "line": reader.line_num, "reason": "%d fields and the header has %d" % (len(row), len(header))})
                continue
            fields = dict(zip(header, row))
            declared_event(events, source, {"record": record, "line": reader.line_num}, "declared_csv", fields.get, mapping, times, category_map, result_map, stats)
    except csv.Error as exc:
        stats["unparsed"] += 1
        stats["read_errors"].append("the CSV reader stopped at record %d, line %d: %s" % (record + 1, reader.line_num, brief(exc, 100)))


def shown_names(names):
    return [seal_head(n, "text") for n in names]


def parse_jsonl(fh, source, events, clock, max_line, stats, mapping, times, category_map, result_map):
    for n, off, length, raw in read_lines(fh, max_line):
        clock.check(1024)
        if raw is None:
            stats["over_limit"] += 1
            stats["problem_lines"].append({"source_id": source["id"], "line": n, "byte_offset": off, "reason": "line over max_line_bytes: located, not read"})
            continue
        line = decode_line(raw).strip()
        if not line:
            stats["blank"] += 1
            continue
        try:
            obj = json.loads(line)
        except (ValueError, RecursionError):
            stats["unparsed"] += 1
            if len(stats["problem_lines"]) < 200:
                stats["problem_lines"].append({"source_id": source["id"], "line": n, "byte_offset": off, "reason": "not a JSON value (or nested too deeply)"})
            continue
        if not isinstance(obj, dict):
            stats["unparsed"] += 1
            if len(stats["problem_lines"]) < 200:
                stats["problem_lines"].append({"source_id": source["id"], "line": n, "byte_offset": off, "reason": "a JSON value that is not an object"})
            continue
        declared_event(events, source, {"line": n, "byte_offset": off, "byte_length": length}, "declared_jsonl", lambda p: get_path(obj, p), mapping, times, category_map, result_map, stats)


class Node:
    __slots__ = ("tag", "attrib", "text", "kids")

    def __init__(self, tag, attrib):
        self.tag, self.attrib, self.text, self.kids = tag, attrib, None, []


def xml_stream(fh, record_tag, on_record, max_bytes, clock, on_over):
    """Feed expat in chunks; every <record_tag> element is built, handed over and dropped, so memory follows one record."""
    import xml.parsers.expat as expat

    def refuse(*_a):
        raise ValueError("a DOCTYPE or ENTITY declaration is refused: no entity is expanded")
    # Memory follows one record, and one record is bounded: its text and attributes together (MAX_XML_RECORD_BYTES), any one
    # field (MAX_FIELD); a record over either is counted and located, never read in part (on_over). What the reader takes in
    # without a callback (a giant tag, attribute list or comment, which expat holds whole) is bounded by MAX_XML_TOKEN.
    state = {"stack": [], "rec": None, "elements": 0, "records": 0, "depth": 0, "last_line": 1, "bytes": 0, "over": None, "calls": 0}

    def start(tag, attrs):
        state["calls"] += 1
        state["depth"] += 1
        if state["depth"] > MAX_XML_DEPTH:
            raise ValueError("nested deeper than %d" % MAX_XML_DEPTH)
        name = tag.rsplit(":", 1)[-1]
        if state["rec"] is None:
            if name == record_tag:
                state["rec"] = Node(name, attrs)
                state["stack"] = [state["rec"]]
                state["elements"] = 1
                state["bytes"] = sum(len(k) + len(v) for k, v in attrs.items())
                state["over"] = None
                if state["bytes"] > MAX_XML_RECORD_BYTES:
                    state["over"] = "its attributes hold more than %d bytes" % MAX_XML_RECORD_BYTES
                    state["rec"].attrib = {}
            return
        state["elements"] += 1
        if state["elements"] > MAX_XML_RECORD_ELEMENTS:
            raise ValueError("a record has more than %d elements" % MAX_XML_RECORD_ELEMENTS)
        size = sum(len(k) + len(v) for k, v in attrs.items())
        if state["over"] is None and state["bytes"] + size > MAX_XML_RECORD_BYTES:
            state["over"] = "it holds more than %d bytes of text and attributes" % MAX_XML_RECORD_BYTES
        node = Node(name, {} if state["over"] else attrs)
        state["bytes"] += 0 if state["over"] else size
        state["stack"][-1].kids.append(node)
        state["stack"].append(node)

    def end(tag):
        state["calls"] += 1
        state["depth"] -= 1
        if state["rec"] is None:
            return
        node = state["stack"].pop()
        if not state["stack"]:
            state["records"] += 1
            if state["over"]:
                on_over(state["records"], parser.CurrentLineNumber, state["over"])
            else:
                on_record(state["rec"], state["records"], parser.CurrentLineNumber)
            state["rec"] = None

    def chars(text):
        state["calls"] += 1
        if state["rec"] is not None and state["stack"] and state["over"] is None:
            node = state["stack"][-1]
            if (len(node.text) if node.text else 0) + len(text) > MAX_FIELD:
                state["over"] = "one of its fields is over %d bytes" % MAX_FIELD
            elif state["bytes"] + len(text) > MAX_XML_RECORD_BYTES:
                state["over"] = "it holds more than %d bytes of text and attributes" % MAX_XML_RECORD_BYTES
            else:
                node.text = (node.text or "") + text
                state["bytes"] += len(text)
            if state["over"]:
                for kept in state["stack"]:
                    kept.text = None
                state["rec"].kids = []

    parser = expat.ParserCreate()
    parser.buffer_text = True
    parser.StartElementHandler, parser.EndElementHandler, parser.CharacterDataHandler = start, end, chars
    parser.StartDoctypeDeclHandler = refuse
    parser.EntityDeclHandler = refuse
    total, quiet = 0, 0
    while True:
        chunk = fh.read(65536)
        total += len(chunk)
        if total > max_bytes:
            raise ValueError("the file is over max_file_bytes (%d)" % max_bytes)
        clock.check()
        calls = state["calls"]
        parser.Parse(chunk, not chunk)
        quiet = quiet + len(chunk) if state["calls"] == calls else 0
        if quiet > MAX_XML_TOKEN:
            raise ValueError("more than %d bytes were read at byte %d without one element or text ending (a tag, an attribute list or a comment that large is not read)" % (MAX_XML_TOKEN, total))
        if not chunk:
            break
    return state["records"]


def xml_get(rec, path):
    """A value of an XML record: 'tag/sub' (text of the first match), '@attr' (an attribute of the record), 'tag@attr';
    MISSING when the element or the attribute is not in the record."""
    node, _, attr = path.partition("@")
    cur = rec
    for part in [p for p in node.split("/") if p]:
        nxt = None
        for k in cur.kids:
            if k.tag == part:
                nxt = k
                break
        if nxt is None:
            return MISSING
        cur = nxt
    if attr:
        return cur.attrib.get(attr, MISSING)
    return (cur.text or "").strip() if (cur is not rec or not node) else (rec.text or "").strip() or None


def parse_xml(fh, source, events, clock, stats, mapping, times, category_map, result_map, record_tag, max_bytes):
    def on_record(rec, number, line):
        declared_event(events, source, {"record": number, "line": line}, "declared_xml", lambda p: xml_get(rec, p), mapping, times, category_map, result_map, stats)

    def on_over(number, line, why):
        stats["over_limit"] += 1
        if len(stats["problem_lines"]) < 200:
            stats["problem_lines"].append({"source_id": source["id"], "record": number, "line": line, "reason": "a record over the reader's budget (%s): located, not read" % why})
    import xml.parsers.expat as expat
    try:
        count = xml_stream(fh, record_tag, on_record, max_bytes, clock, on_over)
    except (expat.ExpatError, ValueError, LookupError, RecursionError, MemoryError) as exc:
        # one file's damage (an encoding the reader does not know is a LookupError) ends the reading of that file only
        stats["read_errors"].append("%s: the XML stopped being readable (%s)" % (source["id"], brief(exc, 160)))
        return
    if count == 0:
        stats["read_errors"].append("%s: no <%s> element in the file" % (source["id"], seal_text(record_tag, "text")))


# ---- the run ---------------------------------------------------------------------------------------------------------

def want_mapping(args):
    mapping = args.get("mapping")
    if not isinstance(mapping, dict):
        fail("a declared format needs mapping: an object naming the field of each of time, action, and (optional) result, actor, object, host, job, message")
    allowed = ("time", "action", "result", "actor", "object", "host", "job", "message")
    for key, value in mapping.items():
        if key not in allowed or not isinstance(value, str) or not value or len(value) > 200:
            fail("mapping holds a key this tool does not know or a value that is not a field name (allowed keys: %s)" % ", ".join(allowed))
    if not mapping.get("time") or not mapping.get("action"):
        fail("mapping needs at least time and action")
    return mapping


def want_map(args, key, allowed):
    value = args.get(key)
    if value is None:
        return {}
    if not isinstance(value, dict) or len(value) > 5000:
        fail("%s must be an object of at most 5000 entries" % key)
    out = {}
    for k, v in value.items():
        if not isinstance(k, str) or len(k) > 200 or v not in allowed:
            fail("%s: every value must be one of %s" % (key, ", ".join(allowed)))
        out[k.lower()] = v
    return out


def main():
    install_stop_handlers()
    args = read_args()
    paths = want_str_list(args, "paths", MAX_PATHS)
    one = want_str(args, "path")
    if one:
        paths = [one] + paths
    if not paths:
        fail("name the exports: path is one file, paths a list of up to %d" % MAX_PATHS)
    fmt = args.get("format", "auto")
    if fmt not in ("auto", "pve_task_index", "pve_vzdump_log", "declared_csv", "declared_jsonl", "declared_xml"):
        fail("format must be auto, pve_task_index, pve_vzdump_log, declared_csv, declared_jsonl or declared_xml")
    product = want_str(args, "product", maximum=200)
    if product and fmt == "auto" and product.lower() not in ("proxmox", "proxmox_ve", "proxmox_backup_server", "pve", "pbs"):
        known = product.lower() in KNOWN_UNSUPPORTED
        fail("product %s is unsupported: no fixture of its format exists, so none is read (%s). Use format declared_csv, declared_jsonl or declared_xml with a mapping you declare." % (
            seal_text(product, "text"), "a product this tool knows it does not read" if known else "this tool does not know it"), status_note="unsupported", unsupported_product=seal_text(product, "text"))
    limit = want_int(args, "limit", DEFAULT_LIMIT, 1, 100000)
    max_line = want_int(args, "max_line_bytes", MAX_LINE, 4096, 16 << 20)
    max_file = want_int(args, "max_file_bytes", 8 << 30, 1 << 20, 64 << 30)
    seconds = want_seconds(args, "max_seconds", DEFAULT_SECONDS, MAX_SECONDS)
    write_text = want_flag(args, "write_text")
    time_format = args.get("time_format", "iso8601")
    if not isinstance(time_format, str) or not (time_format in ("iso8601", "epoch_seconds", "epoch_milliseconds") or (time_format.startswith("strptime:") and 9 < len(time_format) < 120)):
        fail("time_format must be iso8601, epoch_seconds, epoch_milliseconds or strptime:<format>")
    offset = args.get("time_zone_offset_minutes")
    if offset is not None and (isinstance(offset, bool) or not isinstance(offset, int) or abs(offset) > 14 * 60):
        fail("time_zone_offset_minutes must be a whole number of minutes between -840 and 840")
    mapping = category_map = result_map = None
    delimiter, has_header, columns, record_tag = ",", True, None, None
    if fmt.startswith("declared_"):
        mapping = want_mapping(args)
        category_map = want_map(args, "category_map", CATEGORIES)
        result_map = want_map(args, "result_map", RESULTS)
        if fmt == "declared_csv":
            delimiter = args.get("delimiter", ",")
            if not isinstance(delimiter, str) or len(delimiter) != 1 or delimiter in ("\n", "\r", '"'):
                fail("delimiter must be one character")
            has_header = args.get("has_header", True)
            if not isinstance(has_header, bool):
                fail("has_header must be true or false")
            columns = args.get("columns")
            if columns is not None and (not isinstance(columns, list) or not all(isinstance(c, str) and len(c) <= 200 for c in columns) or len(columns) > 1000):
                fail("columns must be a list of at most 1000 names of at most 200 characters")
            if not has_header and not columns:
                fail("a CSV with no header row needs columns")
        if fmt == "declared_xml":
            record_tag = want_str(args, "record_tag", "declared_xml needs record_tag: the element name of one record", maximum=200)
    times = TimeReader(time_format, offset)
    try:
        values = TextFile("audit-values.jsonl", write_text, "JSON Lines, mode 0600: record_type message (seq, source_id, locator, the free-text message of the "
                          "event) or original (where, field, value: the original of a string the answer shows withheld or shortened)")
    except TextRefused as exc:
        fail(str(exc))
    shown = Shower(values)
    bind_run(values, seconds)
    events = Events(limit, shown, values)
    clock = Clock(seconds)
    sources, problems = [], []
    stats = {"parsed": 0, "unparsed": 0, "blank": 0, "over_limit": 0, "problem_lines": [], "mapping_errors": [], "read_errors": [], "unmapped_actions": collections.Counter(), "unmapped_actions_over": 0,
             "fields_absent": collections.Counter(), "records_declared": 0}
    unrecognised = []
    partial = []
    for number, p in enumerate(paths, 1):
        rec = {"id": "S%06d" % number, "path": p}
        try:
            st = os.lstat(p)
        except OSError as exc:
            problems.append({"source_id": rec["id"], "file": shown(p, rec["id"], "file"), "reason": describe(exc)})
            sources.append({"source_id": rec["id"], "file": shown(p, rec["id"], "file"), "state": "unreadable"})
            continue
        if not stat.S_ISREG(st.st_mode):
            problems.append({"source_id": rec["id"], "file": shown(p, rec["id"], "file"), "reason": "not a regular file (a link, a pipe or a device): never opened"})
            sources.append({"source_id": rec["id"], "file": shown(p, rec["id"], "file"), "state": "not_opened"})
            continue
        rec["size"] = st.st_size
        try:
            fd = os.open(p, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
        except OSError as exc:
            problems.append({"source_id": rec["id"], "file": shown(p, rec["id"], "file"), "reason": describe(exc)})
            sources.append({"source_id": rec["id"], "file": shown(p, rec["id"], "file"), "state": "unreadable"})
            continue
        with os.fdopen(fd, "rb") as fh:
            before_n, before_errors = events.n, len(stats["mapping_errors"]) + len(stats["read_errors"])
            kind = fmt
            if fmt == "auto":
                head = fh.read(4096)
                fh.seek(0)
                first = next((l for l in head.decode("utf-8", "replace").splitlines() if l.strip()), "")
                if first.startswith("UPID:"):
                    kind = "pve_task_index"
                elif LOG_PREFIX.match(first):
                    kind = "pve_vzdump_log"
                else:
                    shape = "XML" if first.lstrip().startswith("<") else "JSON" if first.lstrip()[:1] in "{[" else "delimited text" if first.count(",") + first.count("\t") + first.count(";") >= 2 else "text"
                    unrecognised.append({"source_id": rec["id"], "file": shown(p, rec["id"], "file"), "shape": shape,
                                         "reason": "no layout this tool reads was recognised; the file was not parsed. A %s export can be read with format declared_%s and a mapping you declare" % (
                                             shape, {"XML": "xml", "JSON": "jsonl", "delimited text": "csv"}.get(shape, "csv"))})
                    sources.append({"source_id": rec["id"], "file": shown(p, rec["id"], "file"), "size": rec["size"], "state": "unsupported", "shape": shape})
                    continue
            try:
                if rec["size"] > max_file:
                    raise ValueError("the file is %d bytes, over max_file_bytes (%d): named and not read" % (rec["size"], max_file))
                if kind == "pve_task_index":
                    parse_task_index(fh, rec, events, clock, max_line, stats)
                elif kind == "pve_vzdump_log":
                    parse_vzdump_log(fh, rec, events, clock, max_line, stats, times)
                elif kind == "declared_csv":
                    parse_csv(fh, rec, events, clock, max_line, stats, mapping, times, category_map, result_map, delimiter, has_header, columns)
                elif kind == "declared_jsonl":
                    parse_jsonl(fh, rec, events, clock, max_line, stats, mapping, times, category_map, result_map)
                else:
                    parse_xml(fh, rec, events, clock, stats, mapping, times, category_map, result_map, record_tag, max_file)
                state = "parsed"
            except Overtime:
                state = "partial"
                partial.append("the read stopped at max_seconds (%s) in %s: the lines after the last event of that file were not read" % (seconds, rec["id"]))
            except (ValueError, LookupError) as exc:
                state = "failed"
                problems.append({"source_id": rec["id"], "file": shown(p, rec["id"], "file"), "reason": brief(exc, 300)})
            except OSError as exc:
                state = "failed"
                problems.append({"source_id": rec["id"], "file": shown(p, rec["id"], "file"), "reason": "a read failed (%s)" % describe(exc)})
            if state == "parsed" and len(stats["mapping_errors"]) + len(stats["read_errors"]) > before_errors:
                state = "partial" if events.n > before_n else "failed"     # this file's own errors, not an earlier file's
            sources.append({"source_id": rec["id"], "file": shown(p, rec["id"], "file"), "size": rec["size"], "format": kind, "state": state, "events": events.n - before_n})
        if clock.left() <= 0:
            partial.append("max_seconds (%s) was reached: the files after %s were not read" % (seconds, rec["id"]))
            break
    if mapping and stats["records_declared"]:
        for name in ("time", "action"):
            if stats["fields_absent"].get(name):
                partial.append("the declared %s field (%s) is absent from %d of %d record(s): those events carry no %s" % (
                    name, shown(mapping[name], "mapping", name), stats["fields_absent"][name], stats["records_declared"], name))
    if mapping and events.n and not events.time_derived and stats["fields_absent"].get("time", 0) < stats["records_declared"]:
        partial.append("the declared time field never parsed under time_format %s in any of %d event(s): every event is untimed (the reasons are in time.not_derived_reasons)" % (
            time_format if time_format in ("iso8601", "epoch_seconds", "epoch_milliseconds") else "strptime", events.n))
    values.close()
    page = events.page.finish()
    unmapped = sorted(stats["unmapped_actions"].items(), key=lambda kv: -kv[1])[:50]
    not_whole = [s for s in sources if s["state"] in ("partial", "failed", "unreadable", "not_opened")]
    complete = (not not_whole and not stats["unparsed"] and not stats["over_limit"] and not stats["mapping_errors"] and not stats["read_errors"] and not partial
                and not unrecognised and not problems)
    outcome = status_of(complete, events.n == 0 and bool(problems or unrecognised or stats["mapping_errors"]),
                        "every line or record of every file became an event or was a blank line; nothing was left unread",
                        "%d unparsed line(s) or record(s), %d over the line limit, %d file(s) not read whole, %d file(s) unrecognised%s: the answer names them" % (
                            stats["unparsed"], stats["over_limit"], len(not_whole), len(unrecognised), ("; " + "; ".join(partial)) if partial else ""),
                        "no event could be read")
    print(answer_text({
        "parser": PARSER, **outcome,
        "format_requested": fmt, "product_label": seal_text(product, "text") if product else None,
        "product_label_note": "the caller's label for a declared format; not verified" if product and fmt.startswith("declared_") else None,
        "sources": sources, "unrecognised": unrecognised, "problems": problems,
        "events": events.page.page, "pages": {"events": page},
        "counts": {"events": events.n, "parsed": stats["parsed"], "unparsed": stats["unparsed"], "blank": stats["blank"], "over_line_limit": stats["over_limit"]},
        "problem_lines": stats["problem_lines"][:200], "mapping_errors": stats["mapping_errors"], "read_errors": stats["read_errors"],
        "declared_fields_absent": ({"records": stats["records_declared"], "absent_by_field": dict(stats["fields_absent"]),
                                    "note": "a declared field the record does not have at all (present and empty is not absent); time or action absent makes the answer partial"}
                                   if mapping else None),
        "by_category": dict(events.by_category), "by_result": dict(events.by_result),
        "time": {"derived": events.time_derived, "not_derived": events.time_not_derived, "first_utc": events.first, "last_utc": events.last,
                 "not_derived_reasons": dict(events.time_reasons.most_common(10)), "time_format": time_format, "declared_offset_minutes": offset,
                 "note": "events are in source order, not time order; sort on time_utc where it is set. A time with no zone is not assumed to be UTC."},
        "distinct": {k: {"listed": len(v), "over_cap": events.distinct_over[k], "top": [{"value": a, "count": b} for a, b in v.most_common(20)]} for k, v in events.distinct.items()},
        "unmapped_actions_top": [{"action": a, "count": c} for a, c in unmapped] if fmt.startswith("declared_") else None,
        "unmapped_actions_distinct_over_cap": stats["unmapped_actions_over"] if fmt.startswith("declared_") else None,
        "partial_reasons": partial, "text": values.summary(), "withheld": withheld_summary(shown),
        "truncated": page["truncated"],
        "limits": {"max_line_bytes": max_line, "max_file_bytes": max_file, "max_distinct_per_aggregate": MAX_DISTINCT, "xml_record_elements": MAX_XML_RECORD_ELEMENTS},
        "note": "Each event says what a line or record says happened, where it was read and how its time was read. It is not proof the operation took place as described, that a reported success "
                "was a usable restore point, or who did it: an actor is the account the product wrote. A category is a label from a table (this tool's, or the caller's category_map) for the action's name; "
                "the raw action stays beside it. A job that ended OK is not a restore that worked.",
    }))
    return 0 if outcome["status"] != "failed" else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except SystemExit:
        raise
    except BaseException as exc:  # noqa: BLE001 - never a traceback, never a clean answer for a failure
        fail("unexpected failure: %s" % describe(exc))
