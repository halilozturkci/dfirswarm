#!/usr/bin/env python3
"""Inventory the virtual machines, disks, snapshots and datastores that configuration files and inventory exports name.

The inputs read, from their public descriptions, and no others (a file of any other kind is counted, and a product's
file this tool recognises and does not read is listed as unsupported, never guessed at):

    VMware    .vmx (the VM's configuration: its name, guest OS, hardware version, devices and the disk files it names),
              .vmsd (the snapshot database), and ESXi's vmInventory.xml (the registered VMs' configuration paths)
    libvirt   a domain XML (<domain>: devices, disks with their backing stores), a domain snapshot XML (<domainsnapshot>)
              and a storage pool XML (<pool>)
    Proxmox   a VM or container configuration (/etc/pve/qemu-server/<id>.conf, /etc/pve/lxc/<id>.conf, with its snapshot
              sections; a [special:...] section such as the cloud-init settings is listed as special, not as a snapshot)
              and storage.cfg

What it is and is not. It lists what the files say exist, with the file and the line or element each statement came from.
A configuration that names a VM does not show the VM ran, exists on a host now, or was not deleted; a disk it names is
checked only against the files given, and "not in the set" is a statement about the set. Hyper-V (.vmcx, .vmrs),
VirtualBox (.vbox) and OVF are recognised by name or root element and are not read. The keys of a configuration that this
tool shows are the ones listed in the manifest; every other key is counted, and the names of those that look like
credentials are listed (never their values), so a reader knows a secret sits at that line.

SENSITIVE OUTPUT. A configuration can hold a console password, a cloud-init password, an SSH key or a user-data blob
under a key this tool does not show. Names, paths and values it does show pass the shape check of the shared block
(a token-shaped run or user-info is withheld; a long text is shown cut with its whole length); the original goes to one
private file only when write_text is asked for, in a job. XML files are read with entity declarations refused and the
element count and depth bounded. A credential-like key is named in every section it sits in (a snapshot keeps its own
copy of the settings), and credential-like attributes are named to a cap and counted past it. Every key and value of the
answer and of its paging files passes the one way out (SHARED BOUNDARY), which withholds by shape again and checks what it
wrote; a piece of a path (a datastore, a node, a storage name) is taken from the path after the whole was withheld.
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
import sys
import tempfile
import time
import unicodedata
from pathlib import Path

TOOL = "virtualization_inventory"
PARSER = "virtualization_inventory/1"
DEFAULT_LIMIT = 200
DEFAULT_SECONDS = 50.0          # the manifest allows 60
MAX_SECONDS = 50.0
DEFAULT_MAX_FILE = 16 << 20
MAX_XML_ELEMENTS = 100000
MAX_XML_DEPTH = 64
MAX_LINE = 1 << 16
MAX_LINES = 500000
MAX_RECORDS_PER_FILE = 100000
MAX_NAMED_KEYS = 200

VMX_SHOWN = ("displayname", "guestos", "config.version", "virtualhw.version", "uuid.bios", "uuid.location", "vc.uuid", "memsize", "numvcpus",
             "cpuid.corespersocket", "nvram", "firmware", "vmx.hypervisor", "annotation.present")
VMX_ETHERNET = re.compile(r"^ethernet\d+\.(address|generatedaddress|networkname|virtualdev|present|addresstype)$", re.I)
VMX_DEVICE = re.compile(r"^((?:scsi|ide|sata|nvme)\d+:\d+)\.(\w+)$", re.I)
VMX_DEVICE_SHOWN = ("filename", "present", "devicetype", "mode", "redo", "writethrough", "sharing", "persistent")
SENSITIVE_KEY = re.compile(r"(?<![a-z])(pass(word|wd|phrase)?|secret|token|auth|cred(ential)?s?|userdata|user-data|cipassword|sshkeys?|encryption|vnc|(private|api|access|secret|ssh|license|licence)[-_.]?keys?)(?![a-z])", re.I)
UNSUPPORTED_NAMES = {".vmcx": "Hyper-V virtual machine configuration (binary)", ".vmrs": "Hyper-V runtime state", ".vmgs": "Hyper-V guest state",
                     ".vbox": "VirtualBox machine settings", ".vbox-prev": "VirtualBox machine settings (previous)", ".ovf": "OVF descriptor",
                     ".ova": "OVA archive", ".vmtx": "VMware template configuration", ".vmxf": "VMware team file", ".vmss": "VMware suspended state",
                     ".vmsn": "VMware snapshot state", ".utf16xml": "XML in a UTF-16 or UTF-32 encoding (not read)"}

# A value that is a number, a UUID or a run of hex bytes is shown as it is; anything else that comes from the evidence goes through the shape check.
SAFE_VALUE = re.compile(r"[0-9]{1,12}|[0-9A-Fa-f]{8}(?:-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}|(?:[0-9A-Fa-f]{2}[ -]){3,31}[0-9A-Fa-f]{2}")
# Keys whose values the tool built itself (identifiers, constants, derived times), never the evidence's text.
TOOL_BUILT = {"id", "source_id", "vm", "found", "how", "in_set", "in_set_note", "role", "format", "locator", "note", "credential_note", "time_utc", "time_basis", "node_basis",
              "kind", "layer", "keys_not_shown", "credential_like_keys_total", "description_present", "pending_section_present",
              "comment_lines_not_shown", "configuration_in_set", "index", "line", "element", "first_line", "value_chars"}

VOCABULARY = frozenset()     # words the way out shows as they are (see SHARED BOUNDARY): none here

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
# the pairs of letters that fewer than 50 words in 236,000 of an English word list hold (qz, jx, vk, ...): a word has none of them, random letters have some
_RARE_PAIRS = frozenset((
    "bg bk bq bw bx bz cb cd cf cg cj cm cp cv cw cx cz dk dq dx dz fb fc fd fg fh fj fk fm fn fp fq fs fv fw fx fz gc gj gk gp gq gv gx gz hg hj "
    "hk hq hv hx hz jb jc jd jf jg jh jj jk jl jm jn jp jq jr js jt jv jw jx jy jz kc kd kg kj kq kv kx kz lj lq lx lz md mg mh mj mk mq mt mv mx "
    "mz pd pg pj pk pq pv px pz qa qb qc qd qe qf qg qh qi qj qk ql qm qn qo qp qq qr qs qt qv qw qx qy qz rx sj sx sz tj tk tq tv tx uj uq uu uw "
    "vb vc vd vf vg vh vj vk vl vm vn vp vq vr vs vt vv vw vx vz wc wg wj wp wq wv wx wz xb xd xf xg xj xk xl xm xn xq xr xv xw xx xz yj yk yq yv "
    "yy zb zc zd zf zg zh zj zk zm zn zp zq zr zs zt zv zw zx "
).split())

# The pairs above as a pattern: a letter and one of the letters that rarely follow it (`b[gkqwxz]|c[bdfgjmpvwxz]|...`), for the words a placeholder is followed by.
def _rare_alternatives():
    by_first = {}
    for pair in _RARE_PAIRS:
        by_first.setdefault(pair[0], []).append(pair[1])
    return "|".join("%s[%s]" % (first, "".join(sorted(by_first[first]))) for first in sorted(by_first))


_RARE_RE = _rare_alternatives()
# The value after a name that says it is a secret, found anywhere in the string: the secret word first (glued to whatever comes
# before it, in any case: vncPassword, adminpass, dbPwd; `pass` not after by, com, over, under, tres, encom, sur or im, so that
# bypass: and compass: are words), then `=` or `:` (quotes and a little space allowed), then the value and up to three more words
# of it. An error message's `token: line 3, column 5` is not a value. A value in angle brackets is a value, whatever it holds: only a
# placeholder word the tool knows (<redacted>, <password>, <secret>, <token>, <hidden>, <masked>, <value>, <your-password>, <***> ...) is
# not (_PLACEHOLDER).
_PLACEHOLDER = r"<(?i:redacted|hidden|masked|removed|omitted|secret|password|passwd|passphrase|pwd|pass|token|key|value|placeholder|empty|none|null|unset|your[ _-]?(?:password|secret|token|key)|\*{1,16})?>"
# A placeholder ends where a token ends: `<redacted>Zq7kP2mR` is a value that starts with brackets, and so is `<redacted> Zq7kP2mR` when the word after it is
# built like a secret: 8 or more letters and digits with a digit in them or a small letter before a capital, 8 or more digits, or 8 or more letters of one case
# that are not a word (a pair of letters that fewer than 50 words hold, or four consonants in a row: `<redacted> kqmzvtrb`). Neither is the placeholder, the whole of it is the value.
# A word of one case that reads as a word (`<redacted> successfully`) leaves the placeholder as it is.
_PH_TAIL = (r"(?-i:[ \t]+(?:(?=[A-Za-z0-9]{0,32}[A-Za-z])(?=[A-Za-z0-9]{0,32}(?:[0-9]|[a-z][A-Z]))[A-Za-z0-9]{8,}|[0-9]{8,40}(?![A-Za-z0-9])"
            r"|(?=(?:[a-z]{8,40}|[A-Z]{8,40})(?![A-Za-z0-9]))(?=[A-Za-z]{0,38}(?i:" + _RARE_RE + r"|[b-df-hj-np-tv-xz]{4}))[A-Za-z]{8}))")
_PH_END = r"(?=[\s\"';,&\\<>)\]}]|\.(?:\s|$)|$)(?!" + _PH_TAIL + r")"
# The name of a flag that takes a secret (`-password x`, `--token x`, `--api-key x`): the words below, any word with `secret` in it or ending in `token`, `key` (`-key x`) or `Key`,
# `Token`, `Password`, `Passwd`, `Pwd`, `Pass`, `Passphrase`, `Secret` after a letter or a digit (`--sshKey x`, `--apiToken x`, `-AdminPassword x`, `--sshPass x`), also `pw` and `otp`, also after up to four
# words joined by `-` or `_` (`--db-password x`, `--ssh-key x`, `--master-key x`, `--secret-access-key x`); `--key-file x`, `--keyboard x` and `-keep-alive x` are not (the name ends
# where the flag's value begins).
_FLAG_NAME = (r"(?:[A-Za-z0-9]{1,20}[-_]){0,4}(?:(?i:passw(?:or)?d|passwd|pass(?:[-_]?phrase)?|pwd|pw|otp|[A-Za-z0-9]{0,20}secret[A-Za-z0-9]{0,20}|[A-Za-z0-9]{0,20}token|api[-_]?key|access[-_]?key|key|keypass|storepass|userpass|auth|authorization|bearer|psk|credentials?|community)"
              r"|[A-Za-z0-9]{1,20}(?-i:Key|Token|Password|Passwd|Pwd|Pass|Passphrase|Secret))")
_NAMED_SECRET = re.compile(
    r"(?:(?i:pass[_-]?w(?:or)?d|passwd|passphrase|pwd|secret|token|credentials?|api[_-]?key|access[_-]?key|account[_-]?key|private[_-]?key|master[_-]?key"
    r"|shared[_-]?key|signing[_-]?key|encryption[_-]?key|secret[_-]?key|authorization|bearer|dsn|webhook[_-]?url|connection[_-]?string|ssh[_-]?key"
    r"|snmp[_-]?community|community[_-]?string)"
    r"|(?<![Bb]y)(?<![Cc]om)(?<![Oo]ver)(?<![Uu]nder)(?<![Tt]res)(?<![Ee]ncom)(?<![Ss]ur)(?<![Ii]m)(?i:pass)"
    r"|(?i:pw|auth|sig|sas|otp|psk|pin))s?[0-9]{0,2}(?:\\{0,3}[\"'])?[ \t]{0,2}[=:][ \t]{0,2}(?:\\{0,3}[\"'])?"
    r"((?!line[ \t]+[0-9])(?!" + _PLACEHOLDER + _PH_END + r")(?:(?:<[^<>\"'\n]{0,200}>[^\s\"'<>;,&\\]*|[^\s\"'>;,&\\][^\s\"'<>;,&]*)(?:[ \t]+[^\s\"'<>;,&=:]+){0,3}))")
_NAMED_FLAG = re.compile(r"(?<![\w-])--?" + _FLAG_NAME + r"(?:=|[ \t]+)(?!-)(?!" + _PLACEHOLDER + _PH_END + r")(<[^\s\"']*(?:[ \t]+[^\s\"'<>;,&=:]+)?|[^\s\"']+)")
_NAMED_SET = re.compile(r"(?<![\w-])(?i:set|enable)[ \t]+(?i:passw(?:or)?d|secret|passphrase|token)[ \t]+(?:[0-9][ \t]+)?(?!" + _PLACEHOLDER + _PH_END + r")(<[^\s\"']*(?:[ \t]+[^\s\"'<>;,&=:]+)?|[^\s\"']+)")
# The path of a file given to a flag that takes a key (`--key client.key`, `-key server.key`, `--client-key=admin.key`, `--tls-auth ta.key`, `--private-key ~/.ssh/id_rsa`) is a path and not a key: a name
# that ends in .key .pem .pub .crt .p12 .pfx or .jks (to any flag), or, to a flag that ends in `key`, a path that starts with `~/`, `./`, `../`, `/` and one more `/`, or a drive. No part of it is token-like
# or looks like a stretch of a key.
_KEY_FLAG_END = re.compile(r"key[=\s]*$", re.I)
_KEY_FILE_EXT = re.compile(r"[A-Za-z0-9_./~:\\-]{1,120}\.(?:key|pem|pub|crt|p12|pfx|jks)", re.I)
_KEY_FILE_PATH = re.compile(r"(?:~|\.{1,2})/[A-Za-z0-9_./-]{1,120}|/[A-Za-z0-9_.-]{1,40}(?:/[A-Za-z0-9_.-]{1,40})+|[A-Za-z]:\\[A-Za-z0-9_.\\-]{1,120}", re.I)
_KEY_FILE_PIECES = re.compile(r"[/\\._-]")


def _random_piece(piece):
    """A part of a path that is a stretch of a key: 8 or more letters and digits with a digit among the letters and either both cases or the class changing three times (ed25519 is not one)."""
    if len(piece) < 8 or not piece.isalnum() or _HAS_DIGIT.search(piece) is None or piece.isdigit():
        return False
    return (_HAS_UPPER.search(piece) is not None and _HAS_LOWER.search(piece) is not None) or sum(1 for a, b in zip(piece, piece[1:]) if _cls(a) != _cls(b)) >= 3


def _key_file(flag, value):
    """Whether `value` given to `flag` is the path of a key file and not a key."""
    return (len(value) <= 120 and (_KEY_FILE_EXT.fullmatch(value) is not None or (_KEY_FLAG_END.search(flag) is not None and _KEY_FILE_PATH.fullmatch(value) is not None))
            and not any(_token_like(run) for run in _RUN_CAND.findall(value)) and not any(_random_piece(piece) for piece in _KEY_FILE_PIECES.split(value)))


_LONG_DIGITS = re.compile(r"(?<![0-9])[0-9]{19,}(?![0-9])")
_PRIVATE_KEY = re.compile(r"-----BEGIN [A-Z0-9 ]{0,40}PRIVATE KEY-----.*?(?:-----END [A-Z0-9 ]{0,40}PRIVATE KEY-----|$)", re.S)
# A string none of whose rules can match is passed without the slow path: every rule needs one of these.
_QUICK = re.compile(r"[A-Za-z0-9_+%/=-]{14,}|@|AKIA|ASIA|gh[pousr]_|github_pat_|xox[abeprs]-|sk-|eyJ|(?i:basic|bearer)\s|(?i:set|enable)[ \t]+(?i:pass|secret|token)|[0-9]{19}|[=:]|[-_](?i:pass|pwd|secret|token|api|access|client|auth|bearer|psk)|(?i:key|secret|pass|passw(?:or)?d|passwd|pwd|pw|otp|token|community|credentials?|authorization)[ \t]|[a-z0-9](?:Key|Token|Password|Passwd|Pwd|Pass|Passphrase|Secret)[ \t]|-----BEGIN")
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
    spans += [m.span(1) + ("secret",) for m in _NAMED_FLAG.finditer(part) if not _key_file(part[m.start():m.start(1)], m.group(1))]
    spans += [m.span(1) + ("secret",) for m in _NAMED_SET.finditer(part)]
    spans += [m.span() + ("token-shaped text",) for m in _RUN_CAND.finditer(part) if _token_like(m.group(), False)]
    spans += [(m.start(), m.start() + len(m.group().rstrip(".-")), "token-shaped text") for m in _ID_FREE.finditer(part) if not _id_plausible(m.group().rstrip(".-"), True)]
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
    r"|naa\.[0-9a-fA-F]{16,32}|eui\.[0-9a-fA-F]{16}|wwn-0x[0-9a-fA-F]{16}|vml\.[0-9a-fA-F]{20,40}|vsan:[0-9a-f]{16}-[0-9a-f]{16}"
    r"|iqn\.[0-9]{4}-[0-9]{2}\.[a-z0-9][a-z0-9.-]{0,60}(?::[A-Za-z0-9._-]{1,40})?"
    r"|t10\.[A-Za-z]{2,12}_[A-Za-z0-9 _.-]{1,50}_[A-Za-z0-9]{4,24})(?![A-Za-z0-9])")
# A run of underscores in a t10. id is read by the class beside it, never by two `_+` around it: that pair tried every split of the run
# (`t10.AB` and 4,000 underscores took 3 s). An iqn. or t10. form carries a name the evidence chose, so it is accepted as an id only
# when what it carries is a name and not a stretch of random text (_id_plausible); otherwise it is judged like any other text.
_ID_SEGMENT = re.compile(r"[^_ ]+")


# A piece of a t10. id of 16 to 24 characters that drives really carry and random text is not mistaken for by chance: a 16-digit hexadecimal id (an EUI-64) or a WWN of a maker (Kingston
# 50026B, Samsung 5002538, Crucial 500A075, SanDisk 5001B44, Seagate 5000C5, HGST 5000CCA, WD 50014E, Toshiba 5000039), a run of one or two characters
# (zeros), and a model or serial in which ESXi wrote a hyphen as 2D (WDC_WD40EFRX2D68N32N0, ..._____WD2DWCC7K1234567), in the forms below.
_HEX_ONLY = re.compile(r"[0-9A-Fa-f]+")
_T10_KNOWN = re.compile(r"(?:50026B|5002538|500A075|5001B44|5000C5|5000CCA|50014E|5000039)[0-9A-F]{8,10}")


# A model or a serial in which ESXi wrote a hyphen as 2D is plain only in the forms drives carry: a maker's 2 to 4 letters, the digits that start a model, letters and digits in blocks as models write them, then one or two
# `2D` and a part of 2 to 10 characters (WD40EFRX2D68N32N0, ST4000DM0042D2CV104, MZ7LN256HCHP2D000L2), or a maker's two letters, `2D` and a serial or the rest of a model
# (WD2DWCC7K1234567, MZ2D7LN256HCHP2D000L2); a piece of 22 characters or more is never one. A piece that holds `2D` by chance is judged whole, as every other piece is.
_T10_2D = re.compile(r"[A-Z]{2,4}[0-9]{1,6}(?:[A-Z]{1,5}[0-9]{1,4}){0,2}[A-Z]{0,5}(?:2D[A-Z0-9]{2,10}){1,2}|[A-Z]{2}(?:2D[A-Z0-9]{2,14}){1,2}")


def _letters_plain(piece):
    """Whether a run of letters of one case, 16 or more, reads as words and not as random letters: fewer than two pairs of letters that words rarely hold
    (a compound of two or three words has one at most where they meet), a vowel in one letter of five, and no run of five consonants (y is a consonant here, as in the token test)."""
    low = piece.lower()
    return (sum(1 for k in range(len(low) - 1) if low[k:k + 2] in _RARE_PAIRS) < 2 and sum(c in "aeiou" for c in low) >= 0.2 * len(low) and _NO_VOWEL5.search(low) is None)


def _t10_piece_plain(piece):
    """Whether a piece of a t10. id of 16 characters or more is a model or a serial and not random text: not token-like, or one of the known forms above."""
    if len(set(piece)) <= 2 or _T10_KNOWN.fullmatch(piece) is not None or (len(piece) == 16 and _HEX_ONLY.fullmatch(piece)):      # 16 hexadecimal digits are a 64-bit id (an EUI-64), as in an identifier field
        return True
    if "2D" in piece and len(piece) <= 21 and _HEX_ONLY.fullmatch(piece) is None and _T10_2D.fullmatch(piece) is not None:
        return True
    if piece.isalpha() and (piece.islower() or piece.isupper()):          # one case of letters: the test for a lower-case run is the words' one
        return _letters_plain(piece) and not _token_like(piece)
    return not _token_like(piece)


_LETTER_RUNS = re.compile(r"[a-z]{16,40}|[A-Z]{16,40}")
# A t10. or iqn. id in free text is read by the judgement above too: random text in a serial, a model or a target is not made readable by the id around it.
_ID_FREE = re.compile(r"(?<![A-Za-z0-9])(?:t10\.[A-Za-z0-9_.-]{8,120}|iqn\.[0-9]{4}-[0-9]{2}\.[a-z0-9][a-z0-9.-]{0,60}(?::[A-Za-z0-9._-]{1,40})?)")
_NO_VOWEL5 = re.compile(r"[^aeiou]{5}")


def _id_plausible(text, free=False):
    """Whether an iqn. or t10. id holds names: an iqn. whose domain and target have no token-like run and no run of letters of one case that is not words, a t10. whose vendor, model and
    serial pieces are short or do not mix capitals, small letters and digits as random text does. A GUID or a hexadecimal id is as it is. `free`: the id is in free text, where the
    serial a maker puts after the colon of an iqn. (16 to 31 hexadecimal digits: flasharray.3fa2b1c4d5e6f708) is read as it is, as a bare run of them is."""
    if text.startswith("iqn."):
        return (not any(_token_like(run) for run in _RUN_CAND.findall(text[12:]) if not (free and len(run) < 32 and _HEX_ONLY.fullmatch(run)))
                and all(_letters_plain(run) for run in _LETTER_RUNS.findall(text[12:])))
    if text.startswith("t10."):
        for piece in _ID_SEGMENT.findall(text[4:]):
            if len(piece) >= 16 and (len(piece) > 24 or not _t10_piece_plain(piece)):
                return False
    return True


def _ids_plausible(text):
    """Whether every iqn. and t10. id in `text` holds names. One that holds random text makes the whole string not a name: the words around a random serial
    (t10.ATA_____Model_X_____<serial>) are what made the run of it look like words."""
    return all(_id_plausible(m.group()) for m in _ID_EMBEDDED.finditer(text)) and all(_id_plausible(m.group().rstrip(".-")) for m in _ID_FREE.finditer(text))


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


# a secret's name and the word after it, glued or behind a separator or a space (pwd-Zq7kP2mR, Token Zq7kP2mR, passwordZq7kP2mR); -pass, -auth, -bearer and -psk count
# only with a dash before them, being words (a bypass, an authority) otherwise
_SECRET_THEN = re.compile(r"(?:(?i:passw(?:or)?d|passphrase|pwd|secret|token|credential|api[_-]?key|private[_-]?key|access[_-]?key|account[_-]?key)|(?<=-)(?i:pass|auth|bearer|psk))"
                          r"(?=s?[ \t_.-]*['\"(\[]?([A-Za-z0-9]{1,40}))")
# a flag with its value, after anything but a letter or a digit (`d--pwd x` is a directory named d- and a flag): the layers of free text look at a flag after a space or a quote only
_IDENT_FLAG = re.compile(r"(?<![A-Za-z0-9])--?" + _FLAG_NAME + r"[ \t]+(?!-)\S")
_WORD_PARTS = re.compile(r"[A-Z]+(?![a-z])|[A-Z]?[a-z]+|[0-9]+")
_NO_VOWEL = re.compile(r"[^aeiouy]{4}")


# What a VM, a file or a job is called after the name of a secret and is not a value: a file extension (`Password.vmdk`, `Token.vhdx`, `Secret.qcow2`), a snapshot counter (`-000001`),
# a date (`-20240312`), a short host or service tag (`srv01`, `db02`, `pg14`, `7d4f`), and the `D2024` that Veeam glues to a job name before its time stamp (`Password ManagerD2024-...vbk`).
_FILE_EXT = frozenset((
    "vmdk vmx vmxf vmsd vmsn vmem vmss vmtx vmpl vswp nvram vhd vhdx avhd avhdx vsv vfd vmrs vmcx vrsv qcow qcow2 qed vdi raw img iso ova ovf ovpn bin dat db sql json xml yaml yml toml "
    "ini cfg conf log txt csv bak old tmp lck lock zip gz tar tgz bz2 xz zst 7z vbk vib vbm vrb vsb vlb vcb xva ova pdf key pem crt cer pfx".split()))
_VEEAM_GLUE = re.compile(r"D(?:19|20)[0-9]{2}$")
_DATE8 = re.compile(r"(?:19|20)[0-9]{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12][0-9]|3[01])(?:[0-2][0-9][0-5][0-9][0-5][0-9])?")
_TAG = re.compile(r"(?:[a-z]{2,5}|[A-Z]{2,5}|[A-Z][a-z]{1,4})[0-9]{1,4}")
# product and service words that hold a pair of letters English words rarely do (vmware, vcenter, sqlserver, upgrade, update ...): taken out of a word before it is judged
_TECH_WORDS = re.compile("vmware|vcenter|vsphere|vsan|proxmox|nextcloud|splunk|openvpn|pfsense|opnsense|switch|postgres(?:ql)?|pgsql|mysql|mssql|sqlserver|rabbitmq|kafka|"
                         "upgrad(?:e|ed|es|ing)|updat(?:e|ed|es|ing)|workstation|helpdesk|cloudhsm|hyperv|xenserver|netapp|nutanix|veeam|commvault|cohesity|wsus|sccm|pgbouncer|mongodb|redis|"
                         "kubernetes|openshift|jumpbox|gitlab|github|jfrog|zabbix|ldaps?|radius|kerberos|tacacs|cifs|ntnx|qemu|esxi|smtp|sftp|dhcp|https?|iscsi|ntfs|sshd|nightly|monthly|fortnightly|midnight|lightweight|scratch|snmp|crowdstrike|etcd|vmfs|btrfs|openbsd")


_SHORT_ONE_CASE = re.compile(r"[a-z0-9]{1,4}|[A-Z0-9]{1,4}")
_SHORT_TAG = re.compile(r"[a-z0-9]{1,4}|[A-Z0-9]{1,4}|[A-Z][a-z0-9]{0,3}")
_NAME_TOKEN = re.compile(r"[A-Za-z0-9]+")
_HAS_VOWEL = re.compile(r"[aeiouyAEIOUY]")
_HAS_DIGIT_ANY = re.compile(r"[0-9]")
_YEAR = re.compile(r"(?:19|20)[0-9]{2}")
_PERIOD = re.compile(r"(?:19|20)[0-9]{2}(?:[Qq][1-4]|[Hh][12]|[Ww][0-5][0-9])")        # 2024Q3, 2024H2, 2024W07
# the words a copy, a clone, a template, a backup or a disk file of a snapshot is named with: a tag of four characters (z3r0, A1B2) may be followed by them and by nothing else
_SUFFIX_WORD = re.compile("(?:copy|clone|cloned|template|old|new|bak|backup|snap|snapshot|replica|restore|restored|temp|tmp|test|prod|dev|stage|staging|lab|flat|delta|sesparse|final|orig|archive|disk|base|veeam)[0-9]{0,3}")
_DATE_STAMP = re.compile("D?" + _DATE.pattern + "(?:_[0-9A-Fa-f]{4}(?![0-9A-Za-z]))?")        # Veeam's D2024-10-04T020013_AB12 (before .vbk)


def _word_like(token):
    """Whether a token with letters in it reads as words: letters in words of three or more with vowels (a capitals run of two or three is an acronym), at most four digits and only
    at the end (Vault, Ring, DB, Server01, KeePass); the product words in _TECH_WORDS are taken out before a word is judged."""
    parts = _WORD_PARTS.findall(token)
    if not parts:
        return False
    if parts[-1].isdigit():
        if len(parts[-1]) > 4:
            return False
        parts.pop()
    for i, p in enumerate(parts):
        if p.isdigit():
            return False
        if p.isupper():
            if not 2 <= len(p) <= 3:
                return False
        else:
            low = p.lower()
            if len(p) < 3 or (i > 0 and not p[0].isupper()):
                return False
            if sum(c in "aeiouy" for c in low) < 0.2 * len(p) and _TECH_WORDS.sub("", low):
                return False
            for rest in _TECH_WORDS.sub(" ", low).split():
                if _NO_VOWEL.search(rest) or any(rest[k:k + 2] in _RARE_PAIRS for k in range(len(rest) - 1)):
                    return False
    return True


def _name_class(token, dotted=False, tail="", last=True):
    """What a token after a secret's name is in a name. W: a word (Vault, Ring, DB, Server01, KeePass). E: the extension of a file after a dot. C: a counter or a year (five or six digits that start
    with 0, as a snapshot's -000001; 1900 to 2039; a year with a quarter, a half or a week: 2024Q3). G: a group that is a tag and not a value (a number of up to four digits; a date of eight digits or a time stamp of fourteen; 2 to 5 letters of one
    case and 1 to 4 digits, 7 characters at most; a Veeam job name before the `D2024` its time stamp starts with; and, as the last word of the name only (`last`), four characters or fewer of capitals
    and digits or with a digit among them). V: a value. G, C and E are not given when `+` or `=` follows the token (`tail`), and with a `/` after it the four-character group only of one case: the value
    goes on in the alphabet of a key. A token of more than 40 characters is a value."""
    if len(token) > 40:
        return "V"
    free = tail not in ("+", "=")
    if free and dotted and token.lower() in _FILE_EXT:
        return "E"
    if len(token) <= 3:
        return "W" if token.isalpha() and (token[0].isupper() or _HAS_VOWEL.search(token) is not None) else "G"
    if _VEEAM_GLUE.search(token):
        token = token[:-5]
        if len(token) <= 4 and free:
            return "G"
    if free and _PERIOD.fullmatch(token):
        return "C"
    if token.isdigit():
        if not free:
            return "V"
        if (token[0] == "0" and len(token) <= 6) or _YEAR.fullmatch(token) is not None:
            return "C"
        return "G" if len(token) <= 4 or _DATE8.fullmatch(token) is not None else "V"
    if _word_like(token):
        return "W"
    if free and len(token) <= 7 and _TAG.fullmatch(token) is not None:
        return "G"
    if free and last and (_SHORT_TAG if tail == "" else _SHORT_ONE_CASE).fullmatch(token) is not None and (token.isupper() or _HAS_DIGIT_ANY.search(token) is not None):
        return "G"
    return "V"


def _plain_word(token, dotted=False, tail=""):
    """Whether one word after a secret's name in a name is a word, a tag, a counter, a date or an extension and not a value (see _name_class); as the last word of the name."""
    return _name_class(token, dotted, tail) != "V"


def _bracket_end(rest):
    """Where the bracket (or parenthesis) that is open before `rest` closes: the first `]` or `)` that no `[` or `(` in `rest` opened."""
    depth = 0
    for i, c in enumerate(rest):
        if c in "[(":
            depth += 1
        elif c in "])":
            if depth == 0:
                return i
            depth -= 1
    return len(rest)


def _words_after(text, start, more):
    """Whether every word of `text` from `start` on (the first one after a secret's name or a key flag) is a word, a tag, a counter, a date or an extension, and not a value; two or more groups of 4
    characters or more in a row (`ab12-cd34-ef56`, `1234-5678`) are one value written in parts and are judged as the one word they make together. A date and a time stamp are taken out first.
    The word before a `/` in a path has one more characters in it to come (`more`). Inside brackets the words stop at the closing one."""
    rest = text[start:]
    if text.rfind("[", 0, start) > text.rfind("]", 0, start) or text.rfind("(", 0, start) > text.rfind(")", 0, start):
        rest = rest[:_bracket_end(rest)]                  # the name of a secret inside brackets: what comes after the closing bracket is another name
    body = _DATE_STAMP.sub("-", rest)
    tokens = list(_NAME_TOKEN.finditer(body))
    ends = "/" if more else ""
    dotted = [(body[m.start() - 1] if m.start() else text[start - 1:start]) == "." for m in tokens]
    lasts = [False] * len(tokens)                         # whether only the extension of a file, a figure or two, or a word like `copy` and `template` comes after the token
    after = True
    for i in range(len(tokens) - 1, -1, -1):
        lasts[i] = after
        m = tokens[i]
        word = m.group().lower()
        after = after and (len(word) <= 2 or _SUFFIX_WORD.fullmatch(word) is not None or (dotted[i] and word in _FILE_EXT) or (word[0] == "0" and word.isdigit() and len(word) <= 6)) and body[m.end():m.end() + 1] not in ("+", "=")
    group, last = [], 0
    for i, m in enumerate(tokens):
        token, end = m.group(), m.end()
        kind = _name_class(token, dotted[i], body[end:end + 1] or ends, lasts[i])
        if kind == "V":
            return False
        if kind == "G" and len(token) >= 4:
            group.append(token)
            last = end
        elif kind != "G":
            if len(group) >= 2 and _name_class("".join(group), False, body[last:last + 1] or ends) == "V":
                return False
            group = []
    return len(group) < 2 or _name_class("".join(group), False, body[last:last + 1] or ends) != "V"


# a flag that takes a secret with the value glued to it or after a space (`--master-key X`, `--master-keyX`, `-keyX`, `--sshKeyX`, `--userpassX`, `--communityX`): a name that holds one is a command line.
# The word after the flag is judged like the word after a secret's name; `--key-file`, `--keyboard`, `--keyring-backend` and `--key-size` are words after `--key`. A name without a dash before
# the flag is a name.
_FLAG_THEN = re.compile(r"(?<![A-Za-z0-9])--?" + _FLAG_NAME + r"(?=[ \t_.-]*['\"(\[]?([A-Za-z0-9]{1,40}))")


def _secret_then_value(text, more=False):
    """A name or a path piece that holds a secret's name and then, glued or after a separator or a space, something that is not a word
    (password-Zq7kP2mR, Token Zq7kP2mR, pwdZq7kP2mR, password-srv01-Zq7kP2mR, password-ab12-cd34-ef56) or a flag with its value (-password x, --token x, --master-keyZq7kP2mR, set password x):
    a command line, not a name. Every word after the first secret's name is judged, not the first alone. `more`: a `/` follows the piece in the path it is cut from."""
    if _IDENT_FLAG.search(text) is not None or _NAMED_SET.search(text) is not None:
        return True
    m = _SECRET_THEN.search(text)
    if m is not None and not _words_after(text, m.start(1), more):
        return True
    m = _FLAG_THEN.search(text)
    return m is not None and not _words_after(text, m.start(1), more)


def _ident_text_ok(text, limit, path, slash=False, more=False):
    """The grammar of a name or of one path component."""
    if len(text) > limit:
        return False
    if not text.isascii():
        n = unicodedata.normalize("NFKC", text)
        if any(unicodedata.category(c) in _STRIP_CATS or ord(c) in _FILLERS or not (c.isascii() or c.isalnum()) for c in n):
            return False
        text = "".join(c if c.isascii() else "a" for c in n)
    if len(text) >= 12 and not _ids_plausible(text):
        return False
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
    if _secret_then_value(text, more):             # the name of a secret and a value after it: a flag (-password x), a word that is not a word (password-Zq7kP2mR)
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
        if (_ID_FORMS.fullmatch(body) or _id_is(body)) and not _DENY_IN_IDENT.search(body) and not _secret_then_value(body):        # the ids a name or a path shows (t10., iqn.) are shown in an id field too
            return text
        return _withhold_field(text, field, where)
    if kind == "path":
        parts = _SEP.split(body)
        ok = [i % 2 == 1 or not p or _MARKER.fullmatch(p) is not None or p in OWN_NAMES or _ident_text_ok(p, 255, True, False, parts[i + 1:i + 2] == ["/"]) for i, p in enumerate(parts)]
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
                    if _key_edge(heads[i]) or (len(heads[i]) >= 2 and heads[i].endswith("=") and heads[i].rstrip("=")):      # the padding of a key
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
    if len(edge) >= 8 and least < 8 and _randomish(edge):                 # beside a withheld piece: eight or more characters of one case and digits are a stretch of a key too
        return True
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
_S_IDS = re.compile(r"[0-9A-Fa-f]{8}-(?:[0-9A-Fa-f]{4}-){3}[0-9A-Fa-f]{12}|[0-9A-Fa-f]{8}-[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}|(?:naa|eui|wwn-0x|vml)\.?[0-9A-Fa-f]{16,40}|vsan:[0-9a-f]{16}-[0-9a-f]{16}|t10\.[A-Za-z0-9_.]{8,120}"
                    r"|iqn\.[0-9]{4}-[0-9]{2}\.[a-z0-9][a-z0-9.-]{0,60}(?::[A-Za-z0-9._-]{1,40})?")
_S_MARK = re.compile(r"<[^<>]{0,80}withheld[^<>]{0,100}>")
# a value in angle brackets is a value; only the empty brackets (what a marker leaves) and a placeholder word are not
_S_PH = r"<(?:redacted|hidden|masked|removed|omitted|secret|password|passwd|passphrase|pwd|pass|token|key|value|placeholder|empty|none|null|unset|your[ _-]?(?:password|secret|token|key)|\*{1,16})?>"
# The tail the second check reads after a placeholder as a value (the same judgement as the layers above, written again): a word of 8 or more characters with a digit
# or a small letter before a capital, 8 or more digits, or 8 or more letters of one case that hold a pair of letters words rarely hold or four consonants in a row.
_S_RARE = "|".join("%s[%s]" % (a, "".join(sorted(p[1] for p in _RARE_PAIRS if p[0] == a))) for a in sorted({p[0] for p in _RARE_PAIRS}))
_S_PH_TAIL = (r"(?-i:[ \t]+(?:(?=[A-Za-z0-9]{0,32}[A-Za-z])(?=[A-Za-z0-9]{0,32}(?:[0-9]|[a-z][A-Z]))[A-Za-z0-9]{8,}|[0-9]{8,40}(?![A-Za-z0-9])"
              r"|(?=(?:[a-z]{8,40}|[A-Z]{8,40})(?![A-Za-z0-9]))(?=[A-Za-z]{0,38}(?i:" + _S_RARE + r"|[b-df-hj-np-tv-xz]{4}))[A-Za-z]{8}))")
_S_PH_END = r"(?=[\s\"';,&\\<>)\]}]|\.(?:\s|$)|$)(?!" + _S_PH_TAIL + r")"
# a flag that takes a secret (`-password x`, `--token x`, `--db-password x`, `--ssh-key x`, `-key x`, `--apiToken x`; not `--key-file x` or `--keyboard x`)
_S_FLAG_NAME = (r"(?:[a-z0-9]{1,20}[-_]){0,4}(?:pass(?:w(?:or)?d|[-_]?phrase)?|pwd|pw|otp|[a-z0-9]{0,20}secret[a-z0-9]{0,20}|[a-z0-9]{0,20}token|api[-_]?key|access[-_]?key|key|keypass|storepass|userpass|auth|authorization|bearer|psk|credentials?|community"
                r"|[a-z0-9]{1,20}(?-i:Key|Token|Password|Passwd|Pwd|Pass|Passphrase|Secret))")
_S_FLAG = re.compile(r"(?<![\w-])(?:--?" + _S_FLAG_NAME + r"|(?:set|enable)[ \t]+(?:password|secret|passphrase|token))(?:=|[ \t]+)(?!" + _S_PH + _S_PH_END + r")\S", re.I)
_S_PHM = re.compile(_S_PH + _S_PH_END, re.I)
_S_VALUE = re.compile(r"[^\s\"']+")
# a flag that takes a secret with the value glued to it (`--master-keyX`, `-keyX`, `--sshKeyX`, `--userpassX`): the word glued to it
_S_FLAG_GLUED = re.compile(r"(?<![A-Za-z0-9])--?" + _S_FLAG_NAME + r"([A-Za-z0-9]{5,40})", re.I)


def _s_flag(flat):
    """Whether `flat` holds a flag that takes a secret with a value, except a key file given to a flag that takes a key (--key client.key, --private-key ~/.ssh/id_rsa)."""
    for m in _S_FLAG.finditer(flat):
        v = _S_VALUE.match(flat, m.end() - 1)
        if v is None or not _key_file(m.group()[:-1], v.group()):
            return True
    return False


def _s_glued_random(word):
    """Whether the word glued to a flag that takes a secret is a value and not a word: digits among its letters (two at the end are a counter), capitals among small letters more than once, two of the
    pairs of letters words rarely hold, a run of five consonants or a vowel in fewer than one letter of five; five digits or more."""
    core = word.rstrip("0123456789")
    if not core:
        return len(word) >= 5
    if len(word) - len(core) > 2 or not core.isalpha():
        return True
    low = core.lower()
    return (sum(1 for a, b in zip(core, core[1:]) if a.islower() and b.isupper()) >= 2 or sum(1 for k in range(len(low) - 1) if low[k:k + 2] in _RARE_PAIRS) >= 2
            or _NO_VOWEL5.search(low) is not None or (len(low) >= 6 and sum(c in "aeiou" for c in low) < 0.2 * len(low)))


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


_S_T10_PIECES = re.compile(r"[A-Za-z0-9]+")
_S_LETTERS = re.compile(r"[a-z]{16,40}|[A-Z]{16,40}")


def _s_random_letters(run):
    """16 or more letters of one case with two or more of the pairs words rarely hold (a compound of words has one where they meet at most)."""
    low = run.lower()
    return sum(1 for k in range(len(low) - 1) if low[k:k + 2] in _RARE_PAIRS) >= 2


def _s_id_random(s):
    """Whether a device id of a kind holds random text: for a t10. id a piece of more than 24 characters, or 16 to 24 characters that change class as random text does or
    are letters of one case that are not words; for an iqn. id letters of one case that are not words."""
    if s.startswith("t10."):
        return any(len(piece) > 24 or (len(piece) >= 16 and (_random_run(piece) or (_S_LETTERS.fullmatch(piece) and _s_random_letters(piece)))) for piece in _S_T10_PIECES.findall(s[4:]))
    return s.startswith("iqn.") and any(_s_random_letters(run) for run in _S_LETTERS.findall(s[12:]))


def _s_id_out(m):
    """What a device id of a kind leaves in the text the checks below read: a blank. (One that holds random text is found before this, by _s_id_random.)"""
    return " "


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
    bare = _S_IDS.sub(_s_id_out, flat)
    if _s_named(bare) or _s_flag(flat) or any(_s_glued_random(m.group(1)) for m in _S_FLAG_GLUED.finditer(flat)):
        return "a named secret"
    if ("t10." in flat or "iqn." in flat) and any(_s_id_random(m.group()) for m in _S_IDS.finditer(flat)):
        return "a random-looking run"
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


def iso_epoch(value):
    try:
        number = int(str(value).strip())
        return datetime.datetime(1970, 1, 1, tzinfo=datetime.timezone.utc).__add__(datetime.timedelta(seconds=number)).strftime("%Y-%m-%dT%H:%M:%SZ")
    except (ValueError, OverflowError):
        return None


# ---- XML, bounded ----------------------------------------------------------------------------------------------------

class Node:
    __slots__ = ("tag", "attrib", "text", "kids")

    def __init__(self, tag, attrib):
        self.tag, self.attrib, self.text, self.kids = tag, attrib, None, []

    def __iter__(self):
        return iter(self.kids)


def load_xml(source, limit):
    """(root Node, None) or (None, reason). `source` is read in chunks, never whole. Built on expat directly: a DOCTYPE or an entity declaration is refused whatever the
    encoding, no external entity is fetched, and the element count, the depth and the text of one element are bounded."""
    import xml.parsers.expat as expat

    def refuse(*_a):
        raise ValueError("a DOCTYPE or ENTITY declaration is refused: no entity is expanded")
    state = {"root": None, "count": 0, "stack": []}

    def start(tag, attrs):
        state["count"] += 1
        if state["count"] > MAX_XML_ELEMENTS:
            raise ValueError("more than %d elements" % MAX_XML_ELEMENTS)
        if len(state["stack"]) >= MAX_XML_DEPTH:
            raise ValueError("nested deeper than %d" % MAX_XML_DEPTH)
        node = Node(tag, attrs)
        if state["stack"]:
            state["stack"][-1].kids.append(node)
        elif state["root"] is None:
            state["root"] = node
        state["stack"].append(node)

    def end(_tag):
        state["stack"].pop()

    def chars(text):
        if state["stack"]:
            node = state["stack"][-1]
            if node.text is None or len(node.text) < (1 << 20):
                node.text = (node.text or "") + text

    parser = expat.ParserCreate()
    parser.buffer_text = True
    parser.StartElementHandler = start
    parser.EndElementHandler = end
    parser.CharacterDataHandler = chars
    parser.StartDoctypeDeclHandler = refuse
    parser.EntityDeclHandler = refuse
    total = 0
    try:
        while True:
            chunk = source.read(65536)
            total += len(chunk)
            if total > limit:
                raise ValueError("the file is over max_file_bytes (%d)" % limit)
            if not chunk:
                break
            parser.Parse(chunk, False)
        parser.Parse(b"", True)
    except (expat.ExpatError, ValueError, LookupError, RecursionError, MemoryError) as exc:
        # an encoding the reader does not know (LookupError) is this file's failure, never the run's
        return None, "not well-formed, in an encoding the reader does not know, or over a limit (%s)" % brief(exc, 160)
    return state["root"], None


def local(tag):
    return tag.rsplit(":", 1)[-1] if isinstance(tag, str) else ""


def child(el, name):
    for c in el:
        if local(c.tag) == name:
            return c
    return None


def children(el, name):
    return [c for c in el if local(c.tag) == name]


def text_of(el, name):
    c = child(el, name)
    return (c.text or "").strip() if c is not None else None


# ---- the sink: every record passes through here ----------------------------------------------------------------------

class Sink:
    def __init__(self, limit, shown, index):
        self.shown, self.index = shown, index
        self.pages = {k: LosslessPage(TOOL, k, limit) for k in ("vms", "disks", "snapshots", "datastores", "hosts", "sources")}
        self.counts = collections.Counter()
        self.seq = collections.Counter()
        self.per_file = collections.Counter()
        self.over_cap = collections.Counter()
        self.current_file = None

    def new_id(self, prefix):
        self.seq[prefix] += 1
        return "%s%06d" % (prefix, self.seq[prefix])

    def clean(self, value, key=None, depth=0):
        """The net under every record: a string from the evidence that no call site has checked is checked here."""
        if isinstance(value, str):
            if isinstance(value, Shown) or key in TOOL_BUILT or SAFE_VALUE.fullmatch(value):
                return value
            return self.shown(value, self.current_file["id"], key)
        if key in TOOL_BUILT or depth > 5:
            return value
        if isinstance(value, dict):
            return {k: self.clean(v, k, depth + 1) for k, v in value.items()}
        if isinstance(value, list):
            return [self.clean(v, key, depth + 1) for v in value]
        return value

    def emit(self, kind, row):
        row = self.clean(row)
        fid = self.current_file["id"]
        if self.per_file[fid] >= MAX_RECORDS_PER_FILE:
            self.over_cap[fid] += 1
            return None
        self.per_file[fid] += 1
        self.counts[kind] += 1
        row = {"id": self.new_id({"vms": "V", "disks": "D", "snapshots": "N", "datastores": "T", "hosts": "H"}[kind]), "source_id": fid, **row}
        self.pages[kind].add(row)
        return row["id"]

    def disk_ref(self, vm, rel, name, file_like=True, **fields):
        """A disk file a configuration names: checked against the files given, and nothing else. A storage volume of a
        hypervisor (an LVM volume, a Ceph image) is not a file: it is listed and not looked up."""
        target, how = None, "no_name"
        if name and file_like:
            target, how = self.index.resolve(rel, name)
        elif name:
            how = "storage_volume_not_a_file"
        row = {"vm": vm, "file": self.shown(name, self.current_file["id"], "disk file") if name is not None else None,
               "in_set": ("yes" if target else ("ambiguous" if how == "ambiguous_basename" else "no")) if (name and file_like) else ("not_a_file" if name else "no_name"),
               "found": target["id"] if target else None, "how": how if name else "no_name", **fields}
        if how == "basename_only":
            row["in_set_note"] = "matched by file name alone: the configuration's path is not a path in the set"
        return self.emit("disks", row)


# ---- VMware ----------------------------------------------------------------------------------------------------------

CONFIG_KV = re.compile(r'^\s*([A-Za-z0-9_.:\-]+)\s*=\s*"(.*)"\s*$')


def read_lines(fh):
    n = 0
    while True:
        raw = fh.readline(MAX_LINE + 1)
        if not raw:
            return
        n += 1
        if n > MAX_LINES:
            yield n, None
            return
        if len(raw) > MAX_LINE:
            while raw and not raw.endswith(b"\n"):
                raw = fh.readline(MAX_LINE)
            yield n, ""
            continue
        yield n, raw.decode("utf-8", "surrogateescape").rstrip("\r\n")


def key_report(not_shown, sensitive):
    return {"keys_not_shown": not_shown, "keys_that_look_like_credentials": [dict({"name": e[0], "line": e[1], "value_chars": e[2]}, **({"section": e[3]} if len(e) > 3 else {}))
                                                                             for e in sensitive[:MAX_NAMED_KEYS]],
            "credential_like_keys_total": len(sensitive),
            "note": "a value under such a key is at that line of the file, not in this answer; treat it as a secret to rotate"}


def parse_vmx(fh, sink, rec, shown):
    shown_vals, devices, not_shown, sensitive, bad, capped = {}, collections.OrderedDict(), 0, [], 0, False
    for n, line in read_lines(fh):
        if line is None:
            capped = True
            break
        m = CONFIG_KV.match(line)
        if not m:
            bad += 1 if line.strip() and not line.lstrip().startswith("#") else 0
            continue
        key, value = m.group(1), m.group(2)
        low = key.lower()
        dm = VMX_DEVICE.match(key)
        if low in VMX_SHOWN or VMX_ETHERNET.match(key):
            shown_vals[key] = (value, n)
        elif dm and dm.group(2).lower() in VMX_DEVICE_SHOWN:
            devices.setdefault(dm.group(1), {})[dm.group(2).lower()] = (value, n)
        else:
            not_shown += 1
            if SENSITIVE_KEY.search(key):
                sensitive.append((shown(key, rec["id"], "key"), n, len(value)))
    get = lambda k: shown_vals.get(k, (None, None))[0]
    lowered = {k.lower(): v for k, v in shown_vals.items()}
    vm = sink.emit("vms", {"format": "vmx", "name": shown(lowered.get("displayname", (None,))[0], rec["id"], "displayName"), "guest_os": shown(lowered.get("guestos", (None,))[0], rec["id"], "guestOS"),
                           "config_version": lowered.get("config.version", (None,))[0], "hardware_version": lowered.get("virtualhw.version", (None,))[0],
                           "bios_uuid": lowered.get("uuid.bios", (None,))[0], "location_uuid": lowered.get("uuid.location", (None,))[0],
                           "vcenter_instance_uuid": lowered.get("vc.uuid", (None,))[0], "memory_mb": lowered.get("memsize", (None,))[0], "vcpus": lowered.get("numvcpus", (None,))[0],
                           "firmware": lowered.get("firmware", (None,))[0], "nvram": shown(lowered.get("nvram", (None,))[0], rec["id"], "nvram"),
                           "network_adapters": sorted({k.split(".")[0] for k in shown_vals if VMX_ETHERNET.match(k)}),
                           "network": {k: shown(v[0], rec["id"], k) for k, v in shown_vals.items() if VMX_ETHERNET.match(k)},
                           "locator": {"file": rec["id"], "first_line": 1}, **key_report(not_shown, sensitive)})
    if vm is None:
        return "partial", "record cap reached"
    for dev, fields in devices.items():
        name, line = fields.get("filename", (None, None))
        if name is None:
            continue
        raw_type = fields.get("devicetype", (None,))[0]
        kind = (raw_type or "").lower()        # folded for the comparison only: the value is shown as written, through the shape check
        sink.disk_ref(vm, rec["rel"], name, device=dev, device_type=shown(raw_type, rec["id"], "deviceType") if raw_type else None, present=fields.get("present", (None,))[0],
                      mode=fields.get("mode", (None,))[0], locator={"file": rec["id"], "line": line},
                      role="optical or image" if "cdrom" in kind or name.lower().endswith(".iso") else "disk")
    if capped:
        return "partial", "the file has more than %d lines: read to that point, and what was read is listed" % MAX_LINES
    return ("parsed", None) if not bad else ("parsed", "%d line(s) were neither a key = \"value\" line nor a comment: counted, not read" % bad)


def parse_vmsd(fh, sink, rec, shown):
    entries, top, over, capped = collections.OrderedDict(), {}, 0, False
    for n, line in read_lines(fh):
        if line is None:
            capped = True
            break
        m = CONFIG_KV.match(line)
        if not m:
            continue
        key, value = m.group(1), m.group(2)
        low = key.lower()
        if low in ("snapshot.numsnapshots", "snapshot.current", "snapshot.lastuid"):
            top[low.split(".", 1)[1]] = value
            continue
        sm = re.match(r"^snapshot(\d+)\.(.+)$", key, re.I)
        if not sm:
            continue
        idx = int(sm.group(1))
        if idx not in entries:
            if len(entries) >= MAX_RECORDS_PER_FILE:
                over += 1
                continue
            entries[idx] = {"index": idx, "line": n, "disks": []}
        sub, e = sm.group(2).lower(), entries[idx]
        dm = re.match(r"^disk(\d+)\.(.+)$", sub)
        if dm:
            if dm.group(2) == "filename":
                e["disks"].append((value, n))
        elif sub in ("uid", "filename", "displayname", "parent", "createtimehigh", "createtimelow", "description", "type"):
            e[sub] = (value, n)
    for e in entries.values():
        sid = sink.emit("snapshots", {"vm": None, "format": "vmsd", "index": e["index"], "uid": e.get("uid", (None,))[0], "parent_uid": e.get("parent", (None,))[0],
                                      "name": shown(e.get("displayname", (None,))[0], rec["id"], "displayName"),
                                      "description_present": "description" in e, "state_file": shown(e.get("filename", (None,))[0], rec["id"], "snapshot state file"),
                                      "time_raw": {"createTimeHigh": e.get("createtimehigh", (None,))[0], "createTimeLow": e.get("createtimelow", (None,))[0]},
                                      "time_utc": None, "time_basis": "two raw fields as written; how they encode a time is not decoded here",
                                      "snapshot_database": {"numSnapshots": top.get("numsnapshots"), "current": top.get("current"), "lastUID": top.get("lastuid")},
                                      "locator": {"file": rec["id"], "line": e["line"]}})
        for name, line in e["disks"]:
            sink.disk_ref(sid, rec["rel"], name, role="snapshot disk", locator={"file": rec["id"], "line": line})
    if capped:
        return "partial", "the file has more than %d lines: read to that point, and what was read is listed" % MAX_LINES
    if over:
        return "partial", "%d snapshot index(es) past the cap of %d were counted and not listed" % (over, MAX_RECORDS_PER_FILE)
    return "parsed", None


def vmware_path(path):
    """The datastore a /vmfs/volumes/<datastore>/... path names, which is all this tool takes from the path. The piece
    is taken from the path AFTER the whole was withheld by shape: a token split at `/` is withheld as one, never shown
    piece by piece."""
    m = re.match(r"^/vmfs/volumes/([^/]+)/", seal_head(path, "boundary", "vmxCfgPath") if path else "")
    return m.group(1) if m else None


def parse_vm_inventory_xml(root, sink, rec, shown):
    entries = [c for c in root if local(c.tag) == "ConfigEntry"]
    for i, e in enumerate(entries, 1):
        path = text_of(e, "vmxCfgPath")
        sink.emit("vms", {"format": "esxi_vm_inventory_xml", "name": None, "entry_id": e.attrib.get("id"), "object_id": text_of(e, "objID"),
                          "configuration_path": shown(path, rec["id"], "vmxCfgPath"), "datastore_hint": shown(vmware_path(path), rec["id"], "datastore path"),
                          "configuration_in_set": ("yes" if sink.index.resolve(rec["rel"], path)[0] else "no") if path else "no_name",
                          "locator": {"file": rec["id"], "element": "/ConfigRoot/ConfigEntry[%d]" % i},
                          "note": "a VM registered in the inventory when the file was written; it is not evidence that it ran, still exists, or is on this host now"})
    return ("parsed", None) if entries else ("parsed", "no ConfigEntry element: the file holds no registered VM (or is another layout)")


# ---- libvirt ---------------------------------------------------------------------------------------------------------

def disk_entries(disk, sink, vm, rec, base_loc, shown):
    """A <disk> and its <backingStore> chain, one disk reference per layer."""
    dev = child(disk, "target")
    driver = child(disk, "driver")
    layer, cur, loc = 0, disk, base_loc
    while cur is not None and layer < 256:
        src = child(cur, "source")
        fmt = child(cur, "format")
        name = None
        if src is not None:
            name = src.attrib.get("file") or src.attrib.get("dev") or src.attrib.get("name") or src.attrib.get("volume")
        kind = (cur.attrib.get("type") or "") if cur is not disk else (disk.attrib.get("type") or "")
        proto = src.attrib.get("protocol") if src is not None else None
        if name is not None or layer == 0:
            sink.disk_ref(vm, rec["rel"], name if kind in ("file", "block", "dir", "") else None, layer=layer, role=("disk" if layer == 0 else "backing store"),
                          device=dev.attrib.get("dev") if dev is not None else None, bus=dev.attrib.get("bus") if dev is not None else None,
                          device_type=disk.attrib.get("device"), source_type=kind or None, source_protocol=proto,
                          source_name=shown(name, rec["id"], "disk source") if (kind not in ("file", "block", "dir", "") and name is not None) else None,
                          disk_format=(fmt.attrib.get("type") if fmt is not None else (driver.attrib.get("type") if (driver is not None and layer == 0) else None)),
                          locator={"file": rec["id"], "element": loc})
        nxt = child(cur, "backingStore")
        if nxt is None or (not list(nxt) and not nxt.attrib):
            break
        cur, layer = nxt, layer + 1
        loc += "/backingStore"


def parse_libvirt_domain(root, sink, rec, shown):
    name = text_of(root, "name")
    os_el = child(root, "os")
    type_el = child(os_el, "type") if os_el is not None else None
    mem = child(root, "memory")
    devices = child(root, "devices")
    credential_attrs, credential_total = [], 0
    if devices is not None:
        for i, g in enumerate(children(devices, "graphics"), 1):
            if "passwd" in g.attrib:
                credential_total += 1
                if len(credential_attrs) < MAX_NAMED_KEYS:          # named up to the cap, all counted
                    credential_attrs.append({"where": "/domain/devices/graphics[%d]@passwd" % i, "value_chars": len(g.attrib["passwd"])})
    vm = sink.emit("vms", {"format": "libvirt_domain", "name": shown(name, rec["id"], "name"), "uuid": text_of(root, "uuid"), "virt_type": root.attrib.get("type"),
                           "machine": type_el.attrib.get("machine") if type_el is not None else None, "arch": type_el.attrib.get("arch") if type_el is not None else None,
                           "memory": (mem.text or "").strip() + " " + mem.attrib.get("unit", "KiB") if mem is not None else None,
                           "vcpus": text_of(root, "vcpu"), "locator": {"file": rec["id"], "element": "/domain"},
                           "credential_like_attributes": credential_attrs, "credential_like_attributes_total": credential_total,
                           "credential_note": "a console password sits at that attribute; it is not shown and is a secret to rotate" if credential_attrs else None})
    if devices is None:
        return "parsed", "the domain has no <devices> element"
    for i, d in enumerate(children(devices, "disk"), 1):
        disk_entries(d, sink, vm, rec, "/domain/devices/disk[%d]" % i, shown)
    return "parsed", None


def parse_libvirt_snapshot(root, sink, rec, shown):
    name = text_of(root, "name")
    parent = child(root, "parent")
    dom = child(root, "domain")
    memory = child(root, "memory")
    disks = child(root, "disks")
    sid = sink.emit("snapshots", {"vm": None, "format": "libvirt_domainsnapshot", "name": shown(name, rec["id"], "name"), "uid": None,
                                  "parent_name": shown(text_of(parent, "name") if parent is not None else None, rec["id"], "parent snapshot name"),
                                  "state": text_of(root, "state"), "time_raw": text_of(root, "creationTime"), "time_utc": iso_epoch(text_of(root, "creationTime")),
                                  "time_basis": "creationTime is seconds since 1970-01-01T00:00:00Z", "description_present": bool(text_of(root, "description")),
                                  "memory": memory.attrib.get("snapshot") if memory is not None else None, "domain_name": shown(text_of(dom, "name") if dom is not None else None, rec["id"], "domain name"),
                                  "locator": {"file": rec["id"], "element": "/domainsnapshot"}})
    if disks is not None:
        for i, d in enumerate(children(disks, "disk"), 1):
            src = child(d, "source")
            f = src.attrib.get("file") if src is not None else None
            sink.disk_ref(sid, rec["rel"], f, role="snapshot disk", device=d.attrib.get("name"), snapshot_mode=d.attrib.get("snapshot"), locator={"file": rec["id"], "element": "/domainsnapshot/disks/disk[%d]" % i})
    return "parsed", None


def parse_libvirt_pool(root, sink, rec, shown):
    target = child(root, "target")
    sink.emit("datastores", {"format": "libvirt_pool", "name": shown(text_of(root, "name"), rec["id"], "name"), "type": root.attrib.get("type"), "uuid": text_of(root, "uuid"),
                             "path": shown(text_of(target, "path") if target is not None else None, rec["id"], "path"), "locator": {"file": rec["id"], "element": "/pool"}})
    return "parsed", None


# ---- Proxmox ---------------------------------------------------------------------------------------------------------

PVE_DISK = re.compile(r"^(virtio|scsi|sata|ide|efidisk|tpmstate|unused)(\d*)$")
PVE_SHOWN = ("name", "hostname", "ostype", "machine", "bios", "cores", "sockets", "vcpus", "memory", "boot", "agent", "onboot", "lock", "template", "arch", "cpu", "scsihw", "vmgenid", "protection", "tags")
PVE_SNAP_SHOWN = ("parent", "snaptime", "vmstate", "snapstate", "description")


def pve_ids(rel):
    parts = seal_head(rel, "boundary", "file").split("/")      # the pieces of the path after the whole was judged as a path
    node = parts[parts.index("nodes") + 1] if "nodes" in parts and parts.index("nodes") + 1 < len(parts) - 1 else None
    m = re.match(r"^(\d+)\.conf$", parts[-1])
    return node, (m.group(1) if m else None)


def pve_section_kind(sname):
    """current (the configuration), pending (changes not applied yet), special (Proxmox's own sections such as
    [special:cloudinit], the cloud-init settings last applied) or snapshot (every other section is named by a snapshot)."""
    name = sname.split("#dup")[0]
    if sname == "":
        return "current"
    if name == "PENDING":
        return "pending"
    if name.startswith("special:"):
        return "special"
    return "snapshot"


def parse_pve_conf(fh, sink, rec, shown):
    node, vmid = pve_ids(rec["rel"])
    sections = collections.OrderedDict([("", {"line": 1, "kv": collections.OrderedDict(), "comment_lines": 0})])
    cur, bad, sensitive, not_shown, capped, sections_over = "", 0, [], 0, False, False
    for n, line in read_lines(fh):
        if line is None:
            capped = True
            break
        if not line.strip():
            continue
        if line.startswith("#"):
            sections[cur]["comment_lines"] += 1
            continue
        m = re.match(r"^\[([^\]]*)\]\s*$", line)
        if m:
            cur = m.group(1)
            if cur in sections:
                cur = cur + "#dup%d" % n
            sections[cur] = {"line": n, "kv": collections.OrderedDict(), "comment_lines": 0}
            if len(sections) > MAX_RECORDS_PER_FILE:
                sections_over = True
                del sections[cur]
                break
            continue
        m = re.match(r"^([A-Za-z0-9_\-]+):\s?(.*)$", line)
        if not m:
            bad += 1
            continue
        sections[cur]["kv"][m.group(1)] = (m.group(2), n)
    main = sections[""]["kv"]
    if node:
        sink.emit("hosts", {"node": shown(node, rec["id"], "node"), "node_basis": "a directory name in the path of the configuration file; no host record was read",
                            "locator": {"file": rec["id"]}})
    for sname, sec in sections.items():
        for k, (v, n) in sec["kv"].items():
            if sname == "" and k not in PVE_SHOWN and not PVE_DISK.match(k) and not re.match(r"^net\d+$", k) and k not in PVE_SNAP_SHOWN:
                not_shown += 1
            # a credential-like key is named wherever it sits: a snapshot or a special section keeps its own copy of the settings
            if SENSITIVE_KEY.search(k) and (sname != "" or k not in PVE_SHOWN):
                sensitive.append((shown(k, rec["id"], "key"), n, len(v), "current" if sname == "" else shown(sname.split("#dup")[0], rec["id"], "section")))
    snapshot_names = [s for s in sections if pve_section_kind(s) == "snapshot"]
    special_names = [s for s in sections if pve_section_kind(s) == "special"]
    vm = sink.emit("vms", {"format": "pve_conf", "vmid": vmid, "node": shown(node, rec["id"], "node"), "name": shown((main.get("name") or main.get("hostname") or (None,))[0], rec["id"], "name"),
                           "kind": "container" if "/lxc/" in "/" + rec["rel"] else "qemu", "os_type": (main.get("ostype") or (None,))[0], "machine": (main.get("machine") or (None,))[0],
                           "bios": (main.get("bios") or (None,))[0], "cores": (main.get("cores") or (None,))[0], "sockets": (main.get("sockets") or (None,))[0],
                           "memory_mb": (main.get("memory") or (None,))[0], "lock": (main.get("lock") or (None,))[0], "template": (main.get("template") or (None,))[0],
                           "current_parent_snapshot": shown((main.get("parent") or (None,))[0], rec["id"], "parent snapshot name"),
                           "snapshot_sections": [shown(s.split("#dup")[0], rec["id"], "snapshot") for s in snapshot_names[:MAX_NAMED_KEYS]],
                           "snapshot_sections_total": len(snapshot_names),
                           "snapshot_sections_note": "the first %d section names; every snapshot section is a row of snapshots (paged whole)" % MAX_NAMED_KEYS,
                           "special_sections": [shown(s.split("#dup")[0], rec["id"], "section") for s in special_names[:MAX_NAMED_KEYS]],
                           "special_sections_total": len(special_names),
                           "special_sections_note": "a [special:...] section is Proxmox's own (such as the cloud-init settings last applied), not a snapshot; the first %d are named" % MAX_NAMED_KEYS,
                           "pending_section_present": "PENDING" in sections, "comment_lines_not_shown": sections[""]["comment_lines"],
                           "locator": {"file": rec["id"], "first_line": 1}, **key_report(not_shown, sensitive)})
    for sname, sec in sections.items():
        is_snap = pve_section_kind(sname) == "snapshot"
        label = "snapshot %s" % sname if is_snap else ""
        sid = None
        if is_snap:
            kv = sec["kv"]
            snaptime = (kv.get("snaptime") or (None,))[0]
            sid = sink.emit("snapshots", {"vm": vm, "format": "pve_conf_section", "name": shown(sname.split("#dup")[0], rec["id"], "snapshot"), "uid": None,
                                          "parent_name": shown((kv.get("parent") or (None,))[0], rec["id"], "parent snapshot name"), "time_raw": snaptime, "time_utc": iso_epoch(snaptime) if snaptime else None,
                                          "time_basis": "snaptime is seconds since 1970-01-01T00:00:00Z", "vm_state_volume": shown((kv.get("vmstate") or (None,))[0], rec["id"], "vmstate"),
                                          "snapstate": (kv.get("snapstate") or (None,))[0], "description_present": "description" in kv,
                                          "locator": {"file": rec["id"], "line": sec["line"]}})
        for k, (v, n) in sec["kv"].items():
            m = PVE_DISK.match(k)
            if m or re.match(r"^(mp\d+|rootfs)$", k):
                volume, _, options = v.partition(",")
                storage, _, vol = volume.partition(":")      # each piece is judged as the field it fills (a storage name, a volume path) ...
                if vol and seal_head(volume, "boundary", "volume") != volume:      # ... and the whole is judged first: a secret that spans the `:` withholds both pieces
                    storage = vol = "<withheld: %d bytes, field volume>" % blen(volume)
                opts = dict(o.split("=", 1) for o in options.split(",") if "=" in o) if options else {}
                sink.disk_ref(sid or vm, rec["rel"], volume if (":" in volume or "/" in volume) else None, file_like=bool(re.search(r"\.(qcow2|raw|vmdk|vhdx?|img|iso)$", volume, re.I)), section=sname or "current", device=k, role=("snapshot disk" if is_snap else "disk"),
                              storage=shown(storage, rec["id"], "storage") if vol else None, volume=shown(vol, rec["id"], "volume") if vol else None,
                              size=opts.get("size"), backup=opts.get("backup"), media=opts.get("media"), options_count=len(opts), locator={"file": rec["id"], "line": n})
    if capped:
        return "partial", "the file has more than %d lines: read to that point, and what was read is listed" % MAX_LINES
    if sections_over:
        return "partial", "more than %d sections: the first %d are listed and the rest were not read" % (MAX_RECORDS_PER_FILE, MAX_RECORDS_PER_FILE)
    if len(special_names) > MAX_NAMED_KEYS:
        return "partial", "%d [special:...] sections: the first %d are named and the rest are counted (special_sections_total)" % (len(special_names), MAX_NAMED_KEYS)
    return ("parsed", None) if not bad else ("parsed", "%d line(s) matched no key: value shape: counted, not read" % bad)


def parse_pve_storage(fh, sink, rec, shown):
    cur, capped = None, False
    allowed = ("path", "content", "shared", "nodes", "disable", "prune-backups", "maxfiles", "server", "export", "pool", "vgname", "thinpool", "datastore", "username", "mkdir", "is_mountpoint")
    sensitive, not_shown = [], 0
    def flush():
        if cur is not None:
            sink.emit("datastores", {"format": "pve_storage_cfg", "type": cur["type"], "name": shown(cur["name"], rec["id"], "storage name"),
                                     "settings": {k: shown(v, rec["id"], k) for k, v in cur["kv"].items() if k in allowed},
                                     "locator": {"file": rec["id"], "line": cur["line"]}, **key_report(cur["not_shown"], cur["sensitive"])})
    for n, line in read_lines(fh):
        if line is None:
            capped = True
            break
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if not line[0].isspace():
            m = re.match(r"^([A-Za-z0-9_\-]+):\s+(\S.*)$", line)
            flush()
            cur = {"type": m.group(1), "name": m.group(2).strip(), "kv": {}, "line": n, "not_shown": 0, "sensitive": []} if m else None
            continue
        if cur is None:
            continue
        parts = line.strip().split(None, 1)
        key, value = parts[0], parts[1] if len(parts) > 1 else ""
        if key in allowed:
            cur["kv"][key] = value
        else:
            cur["not_shown"] += 1
            if SENSITIVE_KEY.search(key):
                cur["sensitive"].append((shown(key, rec["id"], "key"), n, len(value)))
    flush()
    if capped:
        return "partial", "the file has more than %d lines: read to that point, and what was read is listed" % MAX_LINES
    return "parsed", None


# ---- dispatch --------------------------------------------------------------------------------------------------------

def classify(rec, head, max_file):
    name = posixpath.basename(rec["rel"]).lower()
    ext = posixpath.splitext(name)[1]
    if head[:2] in (b"\xff\xfe", b"\xfe\xff") or head[:4] in (b"\x00\x00\xfe\xff", b"<\x00?\x00", b"\x00<\x00?", b"<\x00d\x00", b"\x00<\x00d"):
        return "unsupported:.utf16xml"
    stripped = head.lstrip(b"\xef\xbb\xbf \t\r\n")
    if stripped[:1] == b"<":
        pos = 0
        while pos < len(stripped):              # skip an XML declaration and comments by position: no pattern can backtrack over a hostile prefix
            while pos < len(stripped) and stripped[pos:pos + 1] in (b" ", b"\t", b"\r", b"\n"):
                pos += 1
            if stripped.startswith(b"<?", pos):
                end = stripped.find(b"?>", pos)
            elif stripped.startswith(b"<!--", pos):
                end = stripped.find(b"-->", pos)
            elif stripped[pos:pos + 9].upper() in (b"<!DOCTYPE", b"<!ENTITY "):
                return "refused:doctype"
            else:
                break
            if end < 0:
                pos = len(stripped)
                break
            pos = end + (2 if stripped.startswith(b"<?", pos) else 3)
        m = re.match(rb"<([A-Za-z_][\w.\-]*)", stripped[pos:pos + 256])
        tag = m.group(1).decode("ascii", "replace") if m else ""
        if tag == "domain":
            return "libvirt_domain"
        if tag == "domainsnapshot":
            return "libvirt_snapshot"
        if tag == "pool":
            return "libvirt_pool"
        if tag == "ConfigRoot":
            return "vm_inventory_xml" if name in ("vminventory.xml",) or b"vmxCfgPath" in head else "xml_other"
        if tag == "VirtualBox":
            return "unsupported:.vbox"
        if tag in ("Envelope",) or ext == ".ovf":
            return "unsupported:.ovf"
        return "xml_other"
    if ext == ".vmsd":
        return "vmsd"
    if ext == ".vmx":
        return "vmx"
    if name == "storage.cfg":
        return "pve_storage"
    if ext == ".conf" and ("qemu-server/" in rec["rel"] + "" or "/lxc/" in "/" + rec["rel"] or "qemu-server" in rec["rel"]):
        return "pve_conf"
    if ext in UNSUPPORTED_NAMES:
        return "unsupported:" + ext
    if ext == ".conf":
        lines = [l for l in head.decode("utf-8", "replace").splitlines() if l and not l.startswith("#")][:30]
        hits = sum(1 for l in lines if re.match(r"^(boot|cores|memory|ostype|scsihw|sockets|vmgenid|smbios1|bios|machine|net\d+|virtio\d+|scsi\d+|ide\d+|sata\d+|efidisk0|name|cpu|agent|onboot|rootfs|hostname|arch):\s", l))
        if hits >= 3:
            return "pve_conf"
    return "other"


def main():
    install_stop_handlers()
    args = read_args()
    root = want_str(args, "root")
    paths = want_str_list(args, "paths", 100000)
    if root is None and not paths:
        fail("name the evidence: root is a directory of configuration files and exports, paths is a list of files")
    limit = want_int(args, "limit", DEFAULT_LIMIT, 1, 100000)
    max_files = want_int(args, "max_files", 20000, 1, 200000)
    max_entries = want_int(args, "max_entries", 200000, 1, 2000000)
    max_depth = want_int(args, "max_depth", 16, 1, 64)
    max_file = want_int(args, "max_file_bytes", DEFAULT_MAX_FILE, 4096, 256 << 20)
    seconds = want_seconds(args, "max_seconds", DEFAULT_SECONDS, MAX_SECONDS)
    write_text = want_flag(args, "write_text")
    try:
        values = TextFile("inventory-values.jsonl", write_text, "JSON Lines, mode 0600: record_type original, where (a source id), field, value (the original text of "
                          "a name, path or value the answer shows withheld or shortened)")
    except TextRefused as exc:
        fail(str(exc))
    shown = Shower(values)
    bind_run(values, seconds)
    clock = Clock(seconds)
    files = FileSet(shown)
    partial = []
    try:
        files.walk(root, paths, max_files, max_entries, max_depth, clock)
    except Overtime:
        partial.append("the walk stopped at max_seconds (%s): the files after the last one listed were not reached" % seconds)
    if files.truncated:
        partial.append(files.truncated)
    index = Index(files.files)
    sink = Sink(limit, shown, index)
    kinds, other_ext, states = collections.Counter(), collections.Counter(), collections.Counter()
    unreadable = []
    parsers_xml = {"libvirt_domain": parse_libvirt_domain, "libvirt_snapshot": parse_libvirt_snapshot, "libvirt_pool": parse_libvirt_pool, "vm_inventory_xml": parse_vm_inventory_xml}
    parsers_text = {"vmx": parse_vmx, "vmsd": parse_vmsd, "pve_conf": parse_pve_conf, "pve_storage": parse_pve_storage}
    problems = 0
    try:
        for rec in files.files:
            clock.check()
            fh, why = open_regular(rec["path"])
            if fh is None:
                files.note("unreadable", rec["rel"] + ": " + (why or ""))
                continue
            with fh:
                head = fh.read(65536)
                kind = classify(rec, head, max_file)
                kinds[kind.split(":")[0] if kind.startswith(("unsupported", "refused")) else kind] += 1
                if kind == "other":
                    ext = ext_of(rec["rel"])
                    other_ext[ext if (ext in other_ext or len(other_ext) < 2000) else "(other extensions)"] += 1
                    continue
                sink.current_file = rec
                row = {"source_id": rec["id"], "file": shown(rec["rel"], rec["id"], "file"), "size": rec["size"], "kind": kind}
                state, reason = "parsed", None
                before = sum(sink.counts.values())
                try:
                    if kind == "refused:doctype":
                        state, reason = "failed", "a DOCTYPE or ENTITY declaration is refused: no entity is expanded, and the file was not handed to a parser"
                    elif kind.startswith("unsupported:"):
                        state, reason = "unsupported_recognised", "%s: recognised and not read" % UNSUPPORTED_NAMES.get(kind.split(":", 1)[1], "a product file")
                    elif kind == "xml_other":
                        state, reason = "unsupported_recognised", "an XML file whose root is not one this tool reads"
                    elif rec["size"] > max_file:
                        state, reason = "failed", "the file is %d bytes, over max_file_bytes (%d): named and not read" % (rec["size"], max_file)
                    elif kind in parsers_xml:
                        fh.seek(0)
                        xml_root, err = load_xml(fh, max_file)
                        if xml_root is None:
                            state, reason = "failed", err
                        else:
                            state, reason = parsers_xml[kind](xml_root, sink, rec, shown)
                    elif kind in parsers_text:
                        fh.seek(0)
                        state, reason = parsers_text[kind](fh, sink, rec, shown)
                except (ValueError, LookupError, OverflowError, RecursionError, MemoryError, IndexError, KeyError, AttributeError) as exc:
                    state, reason = "failed", "the structure could not be read (%s)" % describe(exc)
                except OSError as exc:
                    state, reason = "failed", "a read failed (%s)" % describe(exc)
            if sink.over_cap[rec["id"]]:
                state, reason = "partial", "%d record(s) past the cap of %d for one file were counted and not listed" % (sink.over_cap[rec["id"]], MAX_RECORDS_PER_FILE)
            states[state] += 1
            if state in ("failed", "partial"):
                problems += 1
            row.update(state=state, reason=reason, records=sum(sink.counts.values()) - before)
            sink.pages["sources"].add(row)
    except Overtime:
        partial.append("the examination stopped at max_seconds (%s): the files after the last one listed in sources were not read" % seconds)
    values.close()
    result_pages = {k: v.finish() for k, v in sink.pages.items()}
    unsupported = sum(c for k, c in kinds.items() if k.startswith("unsupported") or k == "xml_other")
    complete = not problems and not partial and not files.skipped_counts["unreadable"] and not files.skipped_counts["too_deep"]
    outcome = status_of(complete, bool(files.files) and not sum(sink.counts.values()) and problems and not unsupported,
                        "every file of a kind this tool reads was read and nothing was left out" + ("; %d file(s) of a recognised kind it does not read are listed as unsupported" % unsupported if unsupported else ""),
                        "%d file(s) were not read whole, %d unreadable, %d directory(ies) too deep%s: the answer names them" % (
                            problems, files.skipped_counts["unreadable"], files.skipped_counts["too_deep"], ("; " + "; ".join(partial)) if partial else ""),
                        "no file could be read")
    recognised = sum(c for k, c in kinds.items() if k != "other")
    if files.files and not recognised and outcome["status"] == "complete":
        outcome = {"status": "complete", "status_basis": "the set holds no file of a kind this tool reads (%d other file(s), counted by extension): zero records is a statement about this tool's formats, not about the system" % sum(other_ext.values())}
    if not files.files:
        skipped = sum(files.skipped_counts.values())
        outcome = ({"status": "partial", "status_basis": "the set holds no file that could be read; %d entr(ies) were skipped (links, special files, directories too deep, unreadable)%s: the answer names them" % (skipped, ("; " + "; ".join(partial)) if partial else "")}
                   if skipped or partial else {"status": "failed", "status_basis": "the set holds no file"})
    print(answer_text({
        "parser": PARSER, **outcome,
        "root": files.root_shown, "files_in_set": len(files.files), "kinds": dict(kinds), "states": dict(states),
        "other_files_by_extension": dict(other_ext.most_common(20)),
        "other_files_note": "files of no kind this tool reads are counted by extension and not examined; absence of a configuration here is not absence of a VM",
        "counts": {"vms": sink.counts["vms"], "disks": sink.counts["disks"], "snapshots": sink.counts["snapshots"], "datastores": sink.counts["datastores"], "hosts": sink.counts["hosts"]},
        "sources": sink.pages["sources"].page, "vms": sink.pages["vms"].page, "disks": sink.pages["disks"].page, "snapshots": sink.pages["snapshots"].page,
        "datastores": sink.pages["datastores"].page, "hosts": sink.pages["hosts"].page, "pages": result_pages,
        "walk": files.skipped_summary(), "walk_truncated": files.truncated, "partial_reasons": partial,
        "text": values.summary(), "withheld": withheld_summary(shown),
        "truncated": any(p["truncated"] for p in result_pages.values()),
        "limits": {"max_files": max_files, "max_entries": max_entries, "max_depth": max_depth, "max_file_bytes": max_file, "max_records_per_file": MAX_RECORDS_PER_FILE,
                   "xml_elements": MAX_XML_ELEMENTS, "xml_depth": MAX_XML_DEPTH},
        "note": "An inventory lists what the files say exist. A configuration or an inventory entry does not show that a VM ran, still exists or was not deleted; a disk 'not in the set' is a "
                "statement about the files given. Versions are the strings the files carry; what they mean for a given product release is for the vendor's documentation of that release.",
    }))
    return 0 if outcome["status"] != "failed" else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except SystemExit:
        raise
    except BaseException as exc:  # noqa: BLE001 - never a traceback, never a clean answer for a failure
        fail("unexpected failure: %s" % describe(exc))
