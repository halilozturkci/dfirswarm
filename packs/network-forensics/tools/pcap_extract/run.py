#!/usr/bin/env python3
"""Export protocol objects from a capture with tshark, index every one, and tie each to the frame it came from where the bytes allow.

What it does, and what it does not:

  * It asks the installed tshark which export object types it has (`--export-objects help`) and records the
    version. An explicitly requested type the build does not list is refused by name before anything is written;
    the default list is cut to the supported ones and the rest is named (protocols_skipped_unsupported). If the
    list cannot be read the passes still run, each failing loudly on its own, and the answer says
    exporters_discovered: false.
  * One deadline, counted from the start of the tool and covering the preflight and every pass (timeout_seconds,
    default 3000, at most 3300 so that this tool stops its passes before the manifest's 3600 seconds do), is kept. A
    pass that uses it up is killed with everything it started; the passes after it are not_attempted and are listed.
    tshark runs in the tool's own process group, not a session of its own: the harness ends a tool by killing its
    group, and an engine outside it would go on writing into the output directory (on Linux the kernel also kills it
    if the tool dies). SIGTERM, SIGINT and SIGHUP kill the pass, leave the receipt as "interrupted" and end the tool.
  * index.tsv and receipt.json exist from the first moment and are replaced (written under a temporary name and
    moved into place) after every pass, so an outer timeout leaves what was done. receipt.json says "running"
    until the last step; a receipt that still says running was cut off.
  * HTTP objects are tied to frames by CONTENT: a second tshark pass lists the HTTP responses with the hex of
    http.file_data, and an object whose SHA-256 equals exactly one listed body, and only one object has it, is
    matched_by_content (frame, stream, time, endpoints, host, request URI). A body that occurs in several frames,
    or an object that several bodies fit, is ambiguous and lists the frames (the whole list of a repeated body is
    in association-candidates.jsonl); an object that matches nothing, or whose protocol has no method here, is
    unmapped and says why. This is a statement about equal bytes, never about a session: whether the exported
    bytes and the field's bytes are the same after content decoding is a property of the tshark build, and an
    object that does not match is unmapped, not absent from the capture. If the listing pass fails, times out or
    holds a row that cannot be read, no association is claimed at all. The listing is read from a pipe as it
    comes and a body is hashed, never held, so no file with the bodies in it is ever written.
  * tshark is a single engine here: an index that agrees with the recipe's tshark listings is agreement of one
    program with itself, not an independent check.

SENSITIVE OUTPUT. Exported objects are evidence content and can hold credentials, cookies and tokens, and so
can their names and the request URIs. The tool follows the secret-safe output pattern (docs/packs.md,
"Secrets and sensitive output"; recovery_key_scan is the reference implementation):

  * The directory is private: mode 0700, every file 0600, including what tshark itself writes (the tool runs
    with umask 077 and sets the modes again after each pass). The answer says out_dir_contains_secret_values and
    names the advice: run the tool as a job with secret_output: true.
  * An object name shaped like a token, or carrying a query string (Wireshark names an HTTP object after the last
    part of its request target, so `login.php%3fuser=bob&pw=x` is a name), is moved to disk as withheld-NNNNNN<ext>
    (never onto a name that is there) and is never printed; the real name is written, at the moment of the rename,
    to withheld-names.jsonl in the output directory (0600) whether or not write_values was given, so that no name
    is lost. A request URI loses its user-info, its token-shaped path text and every query value. The digest of an
    object shorter than 128 bytes is not written (the digest of a short value can be reversed), though it is
    used in memory to match the object to its frame.
  * write_values: true (refused outside a job; created exclusively, mode 0600, before anything runs) writes the
    real names and URIs to $OUT/pcap-extract-values.jsonl and nowhere else. A second run in the same job is
    refused by name and leaves the first file as it was; with nothing withheld the file stays empty and the
    answer says written: 0. Nothing is ever written about a short object's digest, not even there.
  * Nothing is placed on a command line but the capture's path, the output place and the caller's own display
    filter.
"""
import array
import binascii
import datetime
import errno
import hashlib
import json
import os
import re
import select
import shutil
import signal
import stat
import subprocess
import sys
import time
from pathlib import Path

try:
    import ctypes
except ImportError:  # pragma: no cover
    ctypes = None

TOOL = {"name": "pcap_extract", "version": 4}
PARSER = "pcap_extract/4"
DEFAULT_PROTOCOLS = ["http", "smb", "smb2", "tftp", "imf"]
DEFAULT_DEADLINE = 3000
MAX_DEADLINE = 3300           # the manifest's outer limit is 3600: the tool stops its own passes first, so nothing is left running
PREFLIGHT_SECONDS = 30
SHORT_OBJECT = 128            # an object shorter than this has no digest written
MAX_OBJECTS = 200_000         # rows held for the index; files past it stay on disk, are counted, and the run is partial
MAX_FIELD = 4 << 20           # one non-body listing field longer than this makes its row unreadable
LISTED_FRAMES = 20            # frames named in one index cell; the whole list is in association-candidates.jsonl
CELL_LIMIT = 8192
# Export types that have a content-to-frame method here. Every other type is indexed and marked unmapped.
ASSOCIATED = ("http",)
LISTING_FIELDS = ["frame.number", "frame.time_epoch", "tcp.stream", "ip.src", "ipv6.src", "ip.dst", "ipv6.dst",
                  "http.host", "http.response_for.uri", "http.file_data"]
COLUMNS = ["protocol", "name", "path", "bytes", "sha256", "sha256_withheld", "association", "association_reason",
           "frame", "frames", "stream", "time_epoch", "time_utc", "src", "dst", "host", "request_uri", "pass_status"]

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
    return scrub("%s%s: %s" % (type(exc).__name__, " " + code if code else "", getattr(exc, "strerror", None) or str(exc)))


def in_job():
    return bool(os.environ.get("JOB_ID") and os.environ.get("OUT"))


def fail(message, **extra):
    print(json.dumps({"error": scrub(message), "tool": TOOL, **extra}))
    raise SystemExit(1)


def resolve_output(out, what="output"):
    """Where `out` really lands, as a path under the run directory; a place outside it, the run directory itself,
    or anything under inputs/ is refused, and in a job so is anything outside $OUT, the one place a job writes.

    A string check is not enough: `work/../inputs/x`, an absolute path and a symlink that points out all name a
    place the tool must not write. Resolving first and comparing directories is what holds, and the read-only
    inputs are the one place extracted bytes must never appear: a later integrity check would report the
    evidence as modified.
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


class SecretValuesRefused(Exception):
    def __init__(self, message, path=None):
        super().__init__(message)
        self.path = str(path) if path else None


class SecretValues:
    """Where a value goes when, and only when, the caller asked for it.

    The reference implementation of the secret-safe output pattern (recovery_key_scan), with one change: a row is
    written as JSON escapes, so that a name that is not UTF-8 cannot raise. Call `add` once per finding with its
    id, its locator and the value. With `enabled` false it writes nothing and `summary()` says so.
    """

    NAME = "pcap-extract-values.jsonl"

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
                "file, not a sealed secret output. Run this as job_run tool=pcap_extract with "
                "secret_output: true, and ask again there. Nothing was written."
            )
        self.path = Path(self.out) / self.NAME
        self.shown = "store/jobs/%s/out/%s" % (re.sub(r"[^A-Za-z0-9_.-]", "_", self.job), self.NAME)
        # Created now, before anything runs: a file or a link already at that name is refused by name at once
        # (O_EXCL does not follow a link, a dangling one included), instead of failing, or writing through it,
        # after the passes. With nothing withheld it stays an empty file, mode 0600, and the answer says written: 0.
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            fd = os.open(str(self.path), os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        except FileExistsError:
            raise SecretValuesRefused("the values file already exists", self.path)
        except OSError as exc:
            raise SecretValuesRefused("the values file could not be created (%s)" % describe(exc), self.path)
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

    def discard(self):
        """A run that stopped before it wrote a value gives the job its one values file back."""
        if self.enabled and self.written == 0 and self.path is not None:
            self.close()
            try:
                os.unlink(str(self.path))
            except OSError:
                pass

    def summary(self):
        return {
            "requested": self.enabled,
            "written": self.written,
            "values_file": self.shown if self.enabled else None,
            "contains_secret_values": self.written > 0,
            "format": ("JSON Lines, mode 0600: finding_id, protocol, path (as index.tsv names it), request_uri (the whole, "
                       "unredacted), value (the real object name)") if self.enabled else None,
        }


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


def parse_exporters(*texts):
    """The export object types a tshark build lists, in the order it lists them: the indented one-word lines of
    its `--export-objects help` text. Nothing parsed means the list was not read, which is not an empty list."""
    names = []
    for text in texts:
        for line in text.splitlines():
            m = re.fullmatch(r"\s+([A-Za-z0-9][A-Za-z0-9_.-]*)\s*", line)
            if m and m.group(1) not in names:
                names.append(m.group(1))
    return names


# --- the listing pass: HTTP responses and the hash of each body --------------------------------------------

class Listing:
    """Reads the tab-separated listing of HTTP responses from a pipe, one chunk at a time, and keeps for each body
    only what matching needs: the SHA-256 of the decoded hex of the last field, against the digests of the
    exported objects. A body is never held: a response of a gigabyte is hashed as it goes by."""

    def __init__(self, wanted):
        self.wanted = wanted
        self.lines = 0
        self.rows = 0
        self.bodies = 0
        self.unreadable = []                 # line numbers of rows that could not be read
        self.header_ok = None
        self.found = {}                      # digest -> [count, first info, frame numbers]
        self._fields_needed = len(LISTING_FIELDS) - 1
        self._reset()

    def _reset(self):
        self._mode = "prefix"                # prefix: the fields before the body; body: the last field; skip: to the next line
        self._pre = b""
        self._fields = []
        self._parts = []                     # per body of this row: [hasher, length]
        self._carry = b""
        self._bad = False
        self._header = None

    def feed(self, chunk):
        self._feed(chunk)

    def finish(self):
        """The end of the listing: a last line with no line end is still a line."""
        if self._mode == "body":
            self._finish_line()
        elif self._mode == "prefix" and self._pre:
            self._short_line(self._pre)
            self._reset()

    @staticmethod
    def _nth_tab(buf, n):
        pos = -1
        for _ in range(n):
            pos = buf.find(b"\t", pos + 1)
            if pos < 0:
                return -1
        return pos

    def _feed(self, data):
        while data:
            if self._mode == "skip":
                nl = data.find(b"\n")
                if nl < 0:
                    return
                data = data[nl + 1:]
                self._reset()
            elif self._mode == "prefix":
                self._pre += data
                data = b""
                nl = self._pre.find(b"\n")
                tabs = self._nth_tab(self._pre, self._fields_needed)
                if nl >= 0 and (tabs < 0 or nl < tabs):
                    line, data = self._pre[:nl], self._pre[nl + 1:]
                    self._short_line(line)
                    self._reset()
                elif tabs < 0:
                    if len(self._pre) > MAX_FIELD:
                        self._bad_row()
                        self._reset()
                        self._mode = "skip"
                    return
                else:
                    head, data = self._pre[:tabs], self._pre[tabs + 1:]
                    self._fields = head.split(b"\t")
                    self._pre = b""
                    self._mode = "body"
                    self._parts = [[hashlib.sha256(), 0]]
                    self._header = b"" if self.header_ok is None else None
            else:
                nl = data.find(b"\n")
                seg, data = (data, b"") if nl < 0 else (data[:nl], data[nl + 1:])
                if self._header is not None:
                    self._header += seg
                else:
                    self._body(seg)
                if nl >= 0:
                    self._finish_line()

    def _short_line(self, line):
        """A line with fewer fields than were asked for: the header of another listing, a blank line, or a damaged row."""
        self.lines += 1
        if self.header_ok is None:
            self.header_ok = False
        elif line.strip():
            self.unreadable.append(self.lines)

    def _bad_row(self):
        self.lines += 1
        self.unreadable.append(self.lines)

    def _body(self, seg):
        pieces = seg.split(b",")
        for i, piece in enumerate(pieces):
            if i:
                if self._carry:
                    self._bad, self._carry = True, b""
                self._parts.append([hashlib.sha256(), 0])
            data = self._carry + piece.replace(b":", b"").replace(b"\r", b"")
            self._carry = data[-1:] if len(data) % 2 else b""
            data = data[:len(data) - len(data) % 2]
            if not data:
                continue
            try:
                raw = binascii.unhexlify(data)
            except (binascii.Error, ValueError):
                self._bad = True
                continue
            self._parts[-1][0].update(raw)
            self._parts[-1][1] += len(raw)

    def _finish_line(self):
        if self._header is not None:
            tail = self._header.decode("utf-8", "replace").rstrip("\r")
            self.lines += 1
            self.header_ok = [f.decode("utf-8", "replace") for f in self._fields] + [tail] == LISTING_FIELDS
            self._reset()
            return
        self.lines += 1
        if self._carry:
            self._bad = True
        if self._bad:
            self.unreadable.append(self.lines)
            self._reset()
            return
        self.rows += 1
        fields = [f.decode("utf-8", "surrogateescape") for f in self._fields]
        many = len(self._parts) > 1
        info = {"frame": fields[0].strip(), "time_epoch": fields[1], "stream": fields[2], "src": fields[3] or fields[4],
                "dst": fields[5] or fields[6], "host": "" if many else fields[7], "uri": "" if many else fields[8],
                "several_responses_in_frame": many}
        for hasher, size in self._parts:
            if not size:
                continue
            self.bodies += 1
            digest = hasher.hexdigest()
            if digest not in self.wanted:
                continue
            entry = self.found.get(digest)
            if entry is None:
                entry = self.found[digest] = [0, info, array.array("Q")]
            entry[0] += 1
            if info["frame"].isdigit():
                entry[2].append(int(info["frame"]))
        self._reset()


def epoch_to_iso(text):
    """tshark's frame.time_epoch (seconds, a decimal fraction of up to nine digits) as ISO 8601 UTC, digits kept."""
    m = re.fullmatch(r"(-?\d{1,12})(?:\.(\d{1,9}))?", text.strip())
    if not m:
        return ""
    try:
        stamp = datetime.datetime.fromtimestamp(int(m.group(1)), tz=datetime.timezone.utc)
    except (OverflowError, OSError, ValueError):
        return ""
    return stamp.strftime("%Y-%m-%dT%H:%M:%S") + ("." + m.group(2) if m.group(2) else "") + "Z"


# --- the exported objects ---------------------------------------------------------------------------------------

def file_digest(path):
    h = hashlib.sha256()
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    with os.fdopen(fd, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def extension_of(name):
    ext = os.path.splitext(name)[1]
    return ext if re.fullmatch(r"\.[A-Za-z0-9]{1,8}", ext) else ""


def name_withheld(name):
    """A name to keep off the page: shaped like a token, or carrying a query string. Wireshark names an HTTP object
    after the last part of its request target and escapes only a few characters, so `login.php%3fuser=bob&pw=x` is a
    name that holds a query."""
    return token_shaped(name) or "=" in name or re.search(r"%3f", name, re.I) is not None


class Mapping:
    """withheld-names.jsonl: the real name behind every name moved aside, kept in the private output directory and
    written (and flushed) at the moment of the rename, so that nothing is lost whether or not write_values was given."""

    NAME = "withheld-names.jsonl"

    def __init__(self, out_dir):
        self.path = os.path.join(out_dir, self.NAME)
        fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        self.fh = os.fdopen(fd, "w", encoding="utf-8")
        self.count = 0

    def add(self, protocol, shown_path, real_path):
        self.count += 1
        self.fh.write(json.dumps({"finding_id": "N%06d" % self.count, "protocol": protocol, "path": shown_path, "real_path": real_path}) + "\n")
        self.fh.flush()
        os.fsync(self.fh.fileno())

    def close(self):
        if self.fh is not None:
            self.fh.close()
            self.fh = None


class LongCells:
    """A cell over CELL_LIMIT characters is cut in index.tsv and kept whole in index-long-cells.jsonl (named by id)."""

    NAME = "index-long-cells.jsonl"

    def __init__(self, out_dir):
        self.path = os.path.join(out_dir, self.NAME)
        self.ids = {}
        self.fh = None

    def cell(self, key, text):
        if len(text) <= CELL_LIMIT:
            return text
        ident = self.ids.get(key)
        if ident is None:
            if self.fh is None:
                fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
                self.fh = os.fdopen(fd, "w", encoding="utf-8")
            ident = self.ids[key] = "L%06d" % (len(self.ids) + 1)
            self.fh.write(json.dumps({"id": ident, "row": key[0], "column": key[1], "value": text}) + "\n")
            self.fh.flush()
        return text[:CELL_LIMIT] + " ...(%d characters not shown; the whole is %s in %s)" % (len(text) - CELL_LIMIT, ident, self.NAME)

    def close(self):
        if self.fh is not None:
            self.fh.close()
            self.fh = None


class Objects:
    """The rows of the index, and the work of keeping an exported tree private and free of names that are secrets."""

    def __init__(self, out_dir):
        self.out_dir = out_dir
        self.rows = []
        self.mapping = None
        self.long_cells = None
        self.seq = 0                  # withheld-NNNNNN names
        self.names_withheld = 0
        self.not_indexed = 0
        self.short_digests_withheld = 0

    @staticmethod
    def private(top):
        for root, dirs, files in os.walk(top):
            for name in dirs + files:
                full = os.path.join(root, name)
                try:
                    if not os.path.islink(full):
                        os.chmod(full, 0o700 if os.path.isdir(full) else 0o600)
                except OSError:
                    pass

    def collect(self, protocol, status):
        """Index the files a pass left under <out_dir>/<protocol>: private modes first, names that are secrets
        moved aside, every file sized and hashed."""
        top = os.path.join(self.out_dir, protocol)
        self.private(top)
        stack = [(top, "", "")]        # directory on disk, its path as shown, its path as it really was
        while stack:
            directory, shown, real = stack.pop()
            try:
                with os.scandir(directory) as it:
                    entries = sorted(it, key=lambda e: os.fsencode(e.name))
            except OSError as exc:
                self.rows.append(self._row(protocol, "<directory not listed>", shown + "/", None, status, error=describe(exc)))
                continue
            subdirs = []
            for entry in entries:
                name, kept = entry.name, entry.name
                is_dir = entry.is_dir(follow_symlinks=False)
                if name_withheld(name):
                    ext = "" if is_dir else extension_of(name)
                    while True:
                        # never onto a name that is there: a capture can name an object withheld-000001.bin on purpose
                        self.seq += 1
                        kept = "withheld-%06d%s" % (self.seq, ext)
                        if not os.path.lexists(os.path.join(directory, kept)):
                            break
                    self.names_withheld += 1
                    COUNTS["names"] += 1
                    os.rename(os.path.join(directory, name), os.path.join(directory, kept))
                    label = "<name withheld: token-shaped or query-shaped, %d characters>" % len(name)
                    if self.mapping is not None:
                        self.mapping.add(protocol, "%s/%s" % (protocol, (shown + "/" if shown else "") + kept),
                                         "%s/%s" % (protocol, (real + "/" if real else "") + name))
                else:
                    label = name
                rel = (shown + "/" if shown else "") + kept
                real_rel = (real + "/" if real else "") + name
                full = os.path.join(directory, kept)
                if os.path.islink(full):
                    self.rows.append(self._row(protocol, label, rel, None, status, error="a symbolic link, not followed"))
                elif is_dir:
                    subdirs.append((full, rel, real_rel))
                elif len(self.rows) >= MAX_OBJECTS:
                    self.not_indexed += 1
                else:
                    self.rows.append(self._row(protocol, label, rel, full, status, real=real_rel, withheld=kept != name))
            stack.extend(reversed(subdirs))

    def _row(self, protocol, label, rel, full, status, error=None, real=None, withheld=False):
        row = {"protocol": protocol, "name": label, "path": "%s/%s" % (protocol, rel) if rel else protocol,
               "pass_status": status, "real_path": real, "name_withheld": withheld, "bytes": "", "sha": "",
               "sha256": "", "sha256_withheld": "", "request_uri": "", "request_uri_real": ""}
        if error:
            row["association_reason"] = error
        if full is None:
            return row
        try:
            if not stat.S_ISREG(os.lstat(full).st_mode):
                row["association_reason"] = "not a regular file (a named pipe, a device or a socket): not read"
                return row
            size = os.path.getsize(full)
            digest = file_digest(full)
        except OSError as exc:
            row["association_reason"] = "the object could not be read: " + describe(exc)
            return row
        row["bytes"] = size
        row["sha"] = digest
        if size < SHORT_OBJECT:
            self.short_digests_withheld += 1
            row["sha256_withheld"] = ("the object is shorter than %d bytes: the digest of a short value can be reversed, "
                                      "so none is written" % SHORT_OBJECT)
        else:
            row["sha256"] = digest
        return row


def frame_list(frames):
    shown = ",".join(str(f) for f in frames[:LISTED_FRAMES])
    return shown + (",+%d more" % (len(frames) - LISTED_FRAMES) if len(frames) > LISTED_FRAMES else "")


def write_index(path, rows, long_cells=None):
    tmp = path + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as fh:
        fh.write("\t".join(COLUMNS) + "\n")
        for number, row in enumerate(rows, 1):
            fh.write("\t".join(cell(long_cells.cell((number, c), str(row.get(c, ""))) if long_cells else str(row.get(c, ""))) for c in COLUMNS) + "\n")
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, path)


def write_json(path, data):
    tmp = path + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(data, fh, indent=2)
        fh.write("\n")
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, path)


def associate(rows, listing, status, why, candidates_path):
    """Set the association of every row. `listing` is None when the pass did not complete: then nothing is claimed.
    Returns the counts and whether the candidates file was written."""
    counts = {"matched_by_content": 0, "ambiguous": 0, "unmapped": 0, "not_attempted": 0, "failed": 0}
    by_digest = {}
    for row in rows:
        if row["protocol"] in ASSOCIATED and row.get("sha"):
            by_digest.setdefault(row["sha"], []).append(row)
    sets = {}
    for row in rows:
        if row["protocol"] not in ASSOCIATED:
            row["association"] = "unmapped"
            row["association_reason"] = "no content-to-frame association exists here for %s objects; no frame is claimed" % row["protocol"]
        elif not row.get("sha"):
            row["association"] = "unmapped"
            row["association_reason"] = row.get("association_reason") or "the object could not be read, so it was not compared with any response body"
        elif listing is None:
            row["association"] = status
            row["association_reason"] = why
        else:
            entry = listing.found.get(row["sha"])
            objects_with_it = len(by_digest.get(row["sha"], []))
            if entry is None:
                row["association"] = "unmapped"
                row["association_reason"] = "no listed HTTP response body has this object's SHA-256; that does not show the object was not in the capture"
            elif entry[0] == 1 and objects_with_it == 1:
                info = entry[1]
                row["association"] = "matched_by_content"
                row["association_reason"] = ("SHA-256 equal to exactly one listed response body, and to no other exported object"
                                             + ("; the frame holds several responses, so host and request URI are not given" if info["several_responses_in_frame"] else ""))
                row["frame"], row["stream"] = info["frame"], info["stream"]
                row["time_epoch"], row["time_utc"] = info["time_epoch"], epoch_to_iso(info["time_epoch"])
                row["src"], row["dst"], row["host"] = info["src"], info["dst"], info["host"]
                row["request_uri_real"] = info["uri"]
                row["request_uri"] = redact_url(info["uri"]) if info["uri"] else ""
            else:
                set_id = sets.get(row["sha"])
                if set_id is None:
                    set_id = sets[row["sha"]] = "S%06d" % (len(sets) + 1)
                row["association"] = "ambiguous"
                row["frames"] = frame_list(list(entry[2]))
                row["association_reason"] = ("%d listed responses carry this body and %d exported objects have it (candidate_set %s in "
                                             "association-candidates.jsonl); no single frame is claimed" % (entry[0], objects_with_it, set_id))
        counts[row["association"]] = counts.get(row["association"], 0) + 1
    if sets and listing is not None:
        fd = os.open(candidates_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            for digest, set_id in sets.items():
                fh.write(json.dumps({"candidate_set": set_id, "frames": list(listing.found[digest][2]),
                                     "objects": [r["path"] for r in by_digest[digest]]}) + "\n")
        return counts, True
    return counts, False


def stream_listing(argv, stderr_path, seconds, listing):
    """Run the listing pass with its output on a pipe read as it comes; (exit code, killed at the deadline, read error).
    The pipe is read with select, so the deadline is kept without a second thread."""
    with open(stderr_path, "wb") as stderr:
        try:
            proc = spawn(argv, stdout=subprocess.PIPE, stderr=stderr)
        except OSError as exc:
            return None, False, describe(exc)
        ACTIVE.append(proc)
        stop_at = time.monotonic() + seconds
        killed, read_error = False, None
        try:
            fd = proc.stdout.fileno()
            while True:
                left = stop_at - time.monotonic()
                if left <= 0:
                    killed = True
                    kill_tree(proc)
                    break
                ready, _, _ = select.select([fd], [], [], min(1.0, left))
                if not ready:
                    continue
                chunk = os.read(fd, 1 << 20)
                if not chunk:
                    break
                listing.feed(chunk)
            if not killed:
                listing.finish()
        except OSError as exc:
            read_error = describe(exc)
            kill_tree(proc)
        finally:
            try:
                proc.stdout.close()
            except OSError:
                pass
            code = proc.wait()
            ACTIVE.remove(proc)
        return (None if killed else code), killed, read_error


def run_everything(binary, path, out_dir, protocols, display_filter, deadline, objects, runs, errors, state, index_path, receipt, log_dir):
    capture = os.path.abspath(path)
    exhausted = "the shared deadline was used up by an earlier pass"
    for protocol in protocols:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            runs.append({"protocol": protocol, "status": "not_attempted", "reason": exhausted})
            errors.append({"protocol": protocol, "error": "not_attempted", "reason": exhausted})
            receipt("running")
            continue
        destination = os.path.join(out_dir, protocol)
        os.makedirs(destination, mode=0o700, exist_ok=True)
        if os.path.dirname(os.path.realpath(destination)) != os.path.realpath(out_dir):
            runs.append({"protocol": protocol, "status": "failed", "reason": "the export directory is not directly under out_dir: refused"})
            errors.append({"protocol": protocol, "error": "the export directory is not directly under out_dir: refused"})
            receipt("running")
            continue
        argv = [binary, "-n", "-q", "-r", capture]
        if display_filter:
            argv += ["-Y", display_filter]
        argv += ["--export-objects", "%s,%s" % (protocol, destination)]
        stdout_path = os.path.join(log_dir, protocol + ".stdout")
        stderr_path = os.path.join(log_dir, protocol + ".stderr")
        began = time.monotonic()
        code, timed_out = run_to_files(argv, stdout_path, stderr_path, remaining)
        for p in (stdout_path, stderr_path):
            try:
                os.chmod(p, 0o600)
            except OSError:
                pass
        status = "timed_out" if timed_out else ("ok" if code == 0 else "failed")
        before = len(objects.rows)
        objects.collect(protocol, status)
        run = {"protocol": protocol, "status": status, "exit_code": code, "objects": len(objects.rows) - before,
               "seconds": round(time.monotonic() - began, 3), "stdout": stdout_path, "stderr": stderr_path}
        if timed_out:
            run["reason"] = ("the pass was still running when the shared deadline ended and was killed with everything it had started; "
                             "the objects it had written are partial")
            errors.append({"protocol": protocol, "error": "timeout", "after_seconds": state["deadline_seconds"],
                           "stdout": stdout_path, "stderr": stderr_path})
        elif code != 0:
            errors.append({"protocol": protocol, "exit_code": code, "stdout": stdout_path, "stderr": stderr_path})
        runs.append(run)
        for row in objects.rows:
            if "association" not in row:
                row["association"] = "not_attempted"
                row["association_reason"] = row.get("association_reason") or "the association pass has not run yet"
        write_index(index_path, objects.rows, objects.long_cells)
        receipt("running")

    candidates_path = os.path.join(out_dir, "association-candidates.jsonl")
    http_rows = [r for r in objects.rows if r["protocol"] in ASSOCIATED and r.get("sha")]
    listing, status, why = None, "not_attempted", "no HTTP objects were exported, so there was nothing to tie to a frame"
    pass_result = {"status": "not_needed", "reason": why}
    if http_rows:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            status, why = "not_attempted", "the association pass was not attempted: " + exhausted
            pass_result = {"status": "not_attempted", "reason": why}
            errors.append({"pass": "association", "error": "not_attempted", "reason": exhausted})
        else:
            listing = Listing({r["sha"] for r in http_rows})
            argv = [binary, "-n", "-r", capture, "-Y", ("(%s) && http.response" % display_filter) if display_filter else "http.response",
                    "-T", "fields", "-E", "header=y", "-E", "separator=/t", "-E", "occurrence=a", "-E", "aggregator=,"]
            for field in LISTING_FIELDS:
                argv += ["-e", field]
            stderr_path = os.path.join(log_dir, "association.stderr")
            began = time.monotonic()
            code, timed_out, read_error = stream_listing(argv, stderr_path, remaining, listing)
            try:
                os.chmod(stderr_path, 0o600)
            except OSError:
                pass
            pass_result = {"status": "ok", "exit_code": code, "seconds": round(time.monotonic() - began, 3), "stderr": stderr_path,
                           "response_rows": listing.rows, "bodies_hashed": listing.bodies,
                           "rows_unreadable": len(listing.unreadable), "first_unreadable_lines": listing.unreadable[:10]}
            problem = None
            if timed_out:
                problem, pass_result["status"] = "the listing pass was killed at the shared deadline", "timed_out"
            elif read_error:
                problem, pass_result["status"] = "the listing could not be read (%s)" % read_error, "failed"
            elif code != 0:
                problem, pass_result["status"] = "the listing pass exited with code %s" % code, "failed"
            elif listing.header_ok is not True:
                problem, pass_result["status"] = "the listing's header was not the fields asked for, so its columns cannot be trusted", "failed"
            elif listing.unreadable:
                problem, pass_result["status"] = ("%d listing rows could not be read (a body that was not hex, or a row with missing fields)"
                                                  % len(listing.unreadable)), "incomplete"
            if problem:
                listing, status = None, ("not_attempted" if pass_result["status"] == "timed_out" else "failed")
                why = problem + ": no frame is claimed for any object, because a claim from a partial listing could be wrong"
                pass_result["reason"] = why
                errors.append({"pass": "association", "error": pass_result["status"], "reason": why, "stderr": stderr_path})
    counts, wrote = associate(objects.rows, listing, status, why, candidates_path)
    if objects.not_indexed:
        errors.append({"error": "object_cap", "reason": "%d more files are on disk under the protocol directories and are not in index.tsv: "
                                                        "the index holds at most %d objects" % (objects.not_indexed, MAX_OBJECTS)})
    state["association_pass"] = pass_result
    state["association"] = counts
    write_index(index_path, objects.rows, objects.long_cells)
    return wrote


def main():
    started = time.monotonic()
    install_signal_handlers()
    try:
        args = json.load(sys.stdin)
    except ValueError as exc:
        fail("arguments are not valid JSON", reason=str(exc))
    if not isinstance(args, dict):
        fail("arguments must be a JSON object")
    path, out_dir = args.get("path"), args.get("out_dir")
    if not isinstance(path, str) or not path or not os.path.isfile(path):
        fail("path must name a capture file", path=path if isinstance(path, str) else None)
    if not isinstance(out_dir, str) or not out_dir:
        fail("out_dir is required: an empty directory under work/ (in a job, under $OUT)")
    out_dir = resolve_output(out_dir, "out_dir")
    try:
        if os.path.exists(out_dir) and os.listdir(out_dir):
            fail("out_dir already holds files", out_dir=out_dir)
    except OSError as exc:
        fail("out_dir cannot be listed (%s)" % describe(exc), out_dir=out_dir)
    explicit = args.get("protocols")
    if explicit is not None and (not isinstance(explicit, list) or not explicit or any(
            not isinstance(p, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,39}", p) for p in explicit)):
        fail("protocols must be a non-empty list of Wireshark export object type names (letters, digits, - and _; no dot or slash)")
    timeout = args.get("timeout_seconds", DEFAULT_DEADLINE)
    if not isinstance(timeout, int) or isinstance(timeout, bool) or not 1 <= timeout <= MAX_DEADLINE:
        fail("timeout_seconds must be an integer from 1 to %d: one deadline shared by every pass, kept under the 3600-second limit so "
             "that this tool stops its own passes and the limit never has to" % MAX_DEADLINE)
    display_filter = args.get("display_filter")
    if display_filter is not None and (not isinstance(display_filter, str) or not display_filter.strip()):
        fail("display_filter must be a non-empty string")
    write_values = args.get("write_values", False)
    if not isinstance(write_values, bool):
        fail("write_values must be true or false")
    if write_values:
        if not in_job():
            try:
                SecretValues(True)
            except SecretValuesRefused as exc:
                fail(str(exc), write_values="refused", written=False)
        elif os.path.lexists(os.path.join(os.environ["OUT"], SecretValues.NAME)):
            fail("the values file already exists", write_values="refused", written=False,
                 values_file=os.path.join(os.environ["OUT"], SecretValues.NAME))

    binary = shutil.which("tshark")
    if not binary:
        fail("tshark is not on PATH")
    os.umask(0o077)
    deadline = started + timeout
    version_code, version_out, version_err, _ = preflight([binary, "--version"], min(PREFLIGHT_SECONDS, deadline - time.monotonic()))
    _, help_out, help_err, _ = preflight([binary, "--export-objects", "help"], min(PREFLIGHT_SECONDS, deadline - time.monotonic()))
    version_line = ""
    if version_code == 0:
        version_line = (version_out.decode("utf-8", "replace").splitlines() or [""])[0].strip()
    supported = parse_exporters(help_out.decode("utf-8", "replace"), help_err.decode("utf-8", "replace"))
    discovered = bool(supported)

    skipped = []
    if explicit is None:
        protocols = list(DEFAULT_PROTOCOLS)
        if discovered:
            skipped = [p for p in protocols if p not in supported]
            protocols = [p for p in protocols if p in supported]
            if not protocols:
                fail("this tshark build lists none of the default export object types; nothing was written", exporters_supported=supported)
    else:
        protocols = list(dict.fromkeys(explicit))
        if len({p.lower() for p in protocols}) != len(protocols):
            fail("protocols names one export object type twice (a case-insensitive file system would put both in one directory)")
        unknown = [p for p in protocols if discovered and p not in supported]
        if unknown:
            fail("%s %s not export object types of this tshark build; nothing was written" % (", ".join(unknown), "is" if len(unknown) == 1 else "are"),
                 exporters_supported=supported, tshark_version=version_line or None)

    # Everything that can refuse has refused. From here on the tool writes, and the values file comes first.
    try:
        values = SecretValues(write_values)
    except SecretValuesRefused as exc:
        fail(str(exc), write_values="refused", written=False, values_file=exc.path)
    objects = Objects(out_dir)
    index_path = os.path.join(out_dir, "index.tsv")
    receipt_path = os.path.join(out_dir, "receipt.json")
    log_dir = os.path.join(out_dir, "_logs")
    runs, errors = [], []
    state = {
        "tool": TOOL, "parser": PARSER, "status": "running",
        "path": path, "out_dir": out_dir, "index_tsv": index_path, "receipt": receipt_path,
        "tshark_version": version_line or None,
        "display_filter": display_filter,
        "exporters_supported": supported, "exporters_discovered": discovered,
        "protocols_requested": protocols, "protocols_skipped_unsupported": skipped,
        "deadline_seconds": timeout, "runs": runs, "errors": errors,
        "withheld_names_file": Mapping.NAME,
    }

    def receipt(status, why=None):
        state["status"] = status
        state["elapsed_seconds"] = round(time.monotonic() - started, 3)
        state["objects"] = len(objects.rows)
        if why:
            state["why"] = scrub(why)
        write_json(receipt_path, state)

    def write_values_rows():
        """One row per object that has a name or a URI withheld, with the real ones. Written once, at the end, or
        by the last word if the run is stopped."""
        finding = 0
        for row in objects.rows:
            if row.get("name_withheld") or row.get("request_uri_real") != row.get("request_uri"):
                finding += 1
                values.add("O%06d" % finding, {"protocol": row["protocol"], "path": row["path"], "request_uri": row.get("request_uri_real", "")},
                           row.get("real_path") or "")

    def last_word(signum):
        write_values_rows()
        values.close()
        if objects.mapping is not None:
            objects.mapping.close()
        receipt("interrupted", "the tool was stopped by signal %d before it finished" % signum)

    try:
        os.makedirs(log_dir, mode=0o700, exist_ok=True)
        os.chmod(out_dir, 0o700)
        os.chmod(log_dir, 0o700)
        for name, data in (("version.stdout", version_out), ("version.stderr", version_err),
                           ("export-help.stdout", help_out), ("export-help.stderr", help_err)):
            fd = os.open(os.path.join(log_dir, name), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as fh:
                fh.write(data)
        objects.mapping = Mapping(out_dir)
        objects.long_cells = LongCells(out_dir)
        write_index(index_path, [])
        receipt("running")
    except OSError as exc:
        values.discard()
        fail("the output directory could not be created or written (%s)" % describe(exc), out_dir=out_dir)
    STATE["last_word"] = last_word

    try:
        wrote_candidates = run_everything(binary, path, out_dir, protocols, display_filter, deadline, objects, runs, errors,
                                          state, index_path, receipt, log_dir)
    except SystemExit:
        values.close()
        raise
    except BaseException as exc:  # noqa: BLE001 - leave a last word, then fail loudly
        try:
            write_values_rows()
            values.close()
            objects.mapping.close()
            receipt("failed", "unexpected failure: %s" % describe(exc))
        except Exception:  # noqa: BLE001
            pass
        fail("unexpected failure: %s" % describe(exc), out_dir=out_dir)
    try:
        write_values_rows()
    finally:
        values.close()
        objects.mapping.close()
        objects.long_cells.close()

    ok = not errors
    state.update({
        "ok": ok,
        "bytes": sum(r["bytes"] for r in objects.rows if isinstance(r.get("bytes"), int)),
        "objects_not_indexed": objects.not_indexed,
        "association_candidates": "association-candidates.jsonl" if wrote_candidates else None,
        "names_withheld": objects.names_withheld,
        "short_digests_withheld": objects.short_digests_withheld,
        "withheld": dict(COUNTS),
        "secret_values": values.summary(),
        "out_dir_contains_secret_values": bool(objects.rows) or values.written > 0,
        "out_dir_note": ("The output directory holds exported protocol objects, which are evidence content and can carry credentials, "
                         "cookies and tokens, and tshark's own logs. It is private (mode 0700, files 0600). Run this tool as a job with "
                         "secret_output: true so the job output is sealed. A name shaped like a token or carrying a query string is withheld "
                         "as withheld-NNNNNN (the real name is in withheld-names.jsonl in this directory, mode 0600, always), a request URI "
                         "loses its user-info, token-shaped path text and query values, and the digest of an object under 128 bytes is not "
                         "written; write_values: true (jobs only) puts the real names and the whole URIs in one 0600 file under $OUT."),
        "note": ("No object content is returned here. index.tsv names every exported object with its size, SHA-256 (not for an object under "
                 "128 bytes) and, for HTTP objects whose bytes equal exactly one listed response body, its frame, stream, time and endpoints. "
                 "association says how far a frame is claimed: matched_by_content (equal bytes, one frame), ambiguous (the frames are "
                 "listed) or unmapped (and why: the exported bytes can differ from the field's bytes after content decoding, a partial body "
                 "or a response the display filter left out). A frame is where tshark attributes the response, which for a reassembled "
                 "response is where reassembly completed, not necessarily the first packet. "
                 "Preserve the capture's hash and this receipt with any object used in a report. Whether -Y limits what tshark exports, "
                 "whether http.file_data holds the same bytes as the exported object after content decoding, and whether a given exporter "
                 "writes every object are properties of the tshark build named here that this tool does not establish: check an object "
                 "you rely on against the capture. Complete stdout and stderr of every pass are in _logs/."),
    })
    receipt("complete" if ok else "partial")
    print(json.dumps(state, indent=2))
    return 0 if ok else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except SystemExit:
        raise
    except BaseException as exc:  # noqa: BLE001 - never a traceback, never a clean answer for a failure
        fail("unexpected failure: %s" % describe(exc))
