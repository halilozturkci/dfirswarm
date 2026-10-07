#!/usr/bin/env python3
"""Run Zeek over a capture and read its logs back as records, saying what each log holds and what it does not.

What is written, and what is recorded about it:

  * The Zeek version (`zeek --version`, as printed), the command, whether checksums were validated, and the policy
    script. By default the tool writes network-forensics.local.zeek into out_dir, loading
    policy/frameworks/files/hash-all-files, and records its path and SHA-256 (`policies` changes the list; an empty
    list loads nothing). Whether Zeek would hash files without that script is not assumed, and whether the named
    policy exists in the installed build is not either: a build that lacks it fails, and the failure is reported.
    A policy is a name Zeek resolves from its own script path: a path, a name that climbs out of it, or anything
    under inputs/ is refused, because a script from the evidence would be code the evidence supplied.
  * `-C` (ignore checksums) is Zeek's setting for captures taken on an offloading interface, where valid packets
    show bad checksums. checksum_validation: false (the default) passes -C and says so; true leaves checksums on.
  * Every log Zeek wrote stays whole in out_dir, private (mode 0700, files 0600), and is named. Inline records are
    bounded by `limit`; the count of what was not returned is given with the file that holds all of it.
  * The log reader follows the log's own header: #separator, #set_separator, #empty_field, #unset_field, #fields and
    #types, \\xNN escapes, set and vector values as lists, count/int/port as integers, double/interval as numbers,
    bool as T or F, and every `time` field with its raw text kept and a decoded `<name>_utc` beside it. JSON logs
    are read too. A record that does not fit its header (a wrong column count, a value that is not its declared
    type, a line that is not a JSON object, a log with no header) is counted with its line number and byte offset,
    its raw line is kept in malformed-<log>.jsonl, and ok is false: it is never dropped.
  * Requested logs Zeek did not write (logs_requested_not_written) are kept apart from logs it wrote with no
    records (logs_empty). reporter.log, weird.log and capture_loss.log are summarised every time, whatever `logs`
    asks for: they are where an engine says it did not understand the input or lost packets.
  * files.log: hashes_produced says whether any record has a value in a hash column. hash_fields names the hash
    columns the log has, which on a real install can exist whether or not an analyzer filled them, so it is not
    the signal; which hash functions a policy computes is a property of the build. An object shorter than 128 bytes
    has its hash left out of the inline records.
  * Zeek runs in this tool's own process group, not a session of its own: the harness ends a tool by killing its
    group, and an engine outside it would go on writing into the output directory. SIGTERM, SIGINT and SIGHUP kill
    Zeek and what it started. timeout_seconds is held under the manifest's 1200 seconds (at most 1100) for the
    same reason.

SENSITIVE OUTPUT. Zeek logs can carry credentials, cookies, community strings and request URIs (http, ftp, smtp,
ntlm, snmp, rdp and others, depending on the scripts loaded). The directory is private and the answer says to run
the tool as a job with secret_output: true. In the INLINE records a field named like a secret (password, cookie,
community, token ...) is withheld and so is the argument of an FTP PASS; a URL field loses its user-info,
token-shaped path text and query values; and every other string, in any field and in any list, is scrubbed (a
token-shaped run, a key, a JWT, user-info, a Basic or Bearer credential is withheld) except the fields that are
identifiers, hashes, fingerprints, addresses or times. That is by shape: a short secret in free text is not
recognised. Zeek's own log files are kept whole: they are the evidence, and they are in the sealed directory.
"""
import datetime
import errno
import hashlib
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path

TOOL = {"name": "zeek_run", "version": 4}
PARSER = "zeek_run/4"
DEFAULT_TIMEOUT = 900
MAX_TIMEOUT = 1100            # the manifest's outer limit is 1200
DEFAULT_POLICIES = ["policy/frameworks/files/hash-all-files"]
SCRIPT_NAME = "network-forensics.local.zeek"
MAX_LINE = 16 << 20            # a log line longer than this is located, not read
SHORT_OBJECT = 128
DIAGNOSTIC_LOGS = ("reporter", "weird", "capture_loss")
HASH_FIELDS = ("md5", "sha1", "sha256")
SECRET_FIELD = re.compile(r"(?i)(^|[._])(pass(word|wd)?|pwd|secret|token|cookie|community|credentials?|authorization|api_?key|session_?id)($|[._])")
URL_FIELD = re.compile(r"(?i)^(uri|url|full_url|referr?er|origin|post_uri)$")
MAX_NAMES = 10_000

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
    inputs are the one place Zeek's logs must never appear: a later integrity check would report the evidence as
    modified.
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


def epoch_to_iso(text):
    """A Zeek time (seconds since the epoch, with a fraction of up to nine digits) as ISO 8601 UTC, the digits kept.
    Done on integer nanoseconds, so a time before 1970 with a fraction is the instant it names."""
    m = re.fullmatch(r"(-?)(\d{1,12})(?:\.(\d{1,9}))?", text.strip())
    if not m:
        return ""
    sign, whole, frac = m.group(1), int(m.group(2)), m.group(3) or ""
    total = whole * 1_000_000_000 + int((frac + "000000000")[:9])
    if sign:
        total = -total
    seconds, rest = divmod(total, 1_000_000_000)
    try:
        stamp = datetime.datetime.fromtimestamp(seconds, tz=datetime.timezone.utc)
    except (OverflowError, OSError, ValueError):
        return ""
    digits = ("%09d" % rest)[:len(frac)] if frac else ""
    return stamp.strftime("%Y-%m-%dT%H:%M:%S") + ("." + digits if digits else "") + "Z"


def unescape(text):
    """Zeek writes a byte it cannot print, and the separator, as \\xNN; decode those, leave every other backslash alone."""
    if "\\x" not in text:
        return text
    raw = text.encode("utf-8", "surrogateescape")
    raw = re.sub(rb"\\x([0-9a-fA-F]{2})", lambda m: bytes([int(m.group(1), 16)]), raw)
    return raw.decode("utf-8", "surrogateescape")


class BadValue(Exception):
    pass


INTEGER = re.compile(r"-?[0-9]+")
COUNT = re.compile(r"[0-9]+")
DECIMAL = re.compile(r"-?[0-9]+(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?|-?inf|nan")
TIME = re.compile(r"-?[0-9]+(?:\.[0-9]{1,9})?")


def convert(value, typ, set_separator, empty, unset):
    if value == unset:
        return None
    if typ.startswith(("set[", "vector[")):
        inner = typ[typ.index("[") + 1:-1]
        if value == empty:
            return []
        return [convert(v, inner, set_separator, empty, unset) for v in value.split(set_separator)]
    if value == empty and typ == "string":
        return ""
    text = unescape(value)
    if typ in ("count", "port"):
        if not COUNT.fullmatch(text):
            raise BadValue("the value is not a %s" % typ)
        return int(text)
    if typ == "int":
        if not INTEGER.fullmatch(text):
            raise BadValue("the value is not an int")
        return int(text)
    if typ in ("double", "interval"):
        if not DECIMAL.fullmatch(text):
            raise BadValue("the value is not %s %s" % ("an" if typ == "interval" else "a", typ))
        number = float(text)
        # NaN and infinity are not JSON numbers: they stay the text Zeek wrote
        return number if number == number and number not in (float("inf"), float("-inf")) else text
    if typ == "time":
        if not TIME.fullmatch(text):
            raise BadValue("the value is not a time")
        return text
    if typ == "bool":
        if text not in ("T", "F"):
            raise BadValue("the value is not T or F")
        return text == "T"
    return text


class LogReader:
    """One Zeek log, read as a stream: records that fit the header, and a locator for those that do not."""

    def __init__(self, path, stem, limit, malformed_path, hook):
        self.path, self.stem, self.limit, self.malformed_path, self.hook = path, stem, limit, malformed_path, hook
        self.format = None
        self.fields = None
        self.types = None
        self.records = []
        self.parsed = 0
        self.malformed = []
        self.malformed_total = 0
        self.header_problem = None
        self.lines = 0
        self.hash_keys = set()
        self.times_not_decoded = 0
        self._bad = None

    def _flag(self, line_no, offset, why, raw=None):
        self.malformed_total += 1
        if len(self.malformed) < 10:
            self.malformed.append({"log": self.stem, "line": line_no, "byte_offset": offset, "why": scrub(why)})
        if self._bad is None:
            fd = os.open(self.malformed_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
            self._bad = os.fdopen(fd, "w", encoding="utf-8")
        row = {"line": line_no, "byte_offset": offset, "why": why}
        if raw is None:
            row["raw"] = None
            row["raw_kept_in"] = "the log file itself, at this offset (the line is over %d bytes)" % MAX_LINE
        else:
            row["raw"] = raw
        self._bad.write(json.dumps(row) + "\n")

    def read(self):
        separator, set_separator, empty, unset = "\t", ",", "(empty)", "-"
        offset = 0
        with open(self.path, "rb") as fh:
            while True:
                raw = fh.readline(MAX_LINE + 1)
                if not raw:
                    break
                start = offset
                offset += len(raw)
                self.lines += 1
                if len(raw) > MAX_LINE and not raw.endswith(b"\n"):
                    while True:
                        more = fh.readline(MAX_LINE)
                        offset += len(more)
                        if not more or more.endswith(b"\n"):
                            break
                    self._flag(self.lines, start, "a line longer than %d bytes was not read" % MAX_LINE)
                    continue
                line = raw.rstrip(b"\n").decode("utf-8", "surrogateescape")
                if line.startswith("#"):
                    if line.startswith("#separator"):
                        separator = unescape(line.split(" ", 1)[1]) if " " in line else "\t"
                    else:
                        parts = line.split(separator)
                        key, rest = parts[0], parts[1:]
                        if key == "#set_separator" and rest:
                            set_separator = unescape(rest[0])
                        elif key == "#empty_field" and rest:
                            empty = unescape(rest[0])
                        elif key == "#unset_field" and rest:
                            unset = unescape(rest[0])
                        elif key == "#fields":
                            self.fields, self.types, self.header_problem = rest, None, None
                            self.format = self.format or "tsv"
                            self.hash_keys.update(h for h in HASH_FIELDS if h in rest)
                        elif key == "#types":
                            self.types = rest
                            self.header_problem = None
                            if self.fields is not None and len(rest) != len(self.fields):
                                self.header_problem = "the header has %d fields and %d types" % (len(self.fields), len(rest))
                    continue
                if not line.strip():
                    continue
                if self.fields is None:
                    if self.format in (None, "json") and line.lstrip().startswith("{"):
                        self.format = "json"
                    else:
                        self.format = self.format or "tsv"
                        self._flag(self.lines, start, "a record before any #fields header: the columns are unknown", raw=line)
                        continue
                if self.format == "json":
                    try:
                        record = json.loads(line)
                    except ValueError as exc:
                        self._flag(self.lines, start, "not valid JSON (%s)" % str(exc)[:80], raw=line)
                        continue
                    if not isinstance(record, dict):
                        self._flag(self.lines, start, "a JSON value that is not an object", raw=line)
                        continue
                    self.hash_keys.update(h for h in HASH_FIELDS if h in record)
                    if isinstance(record.get("ts"), (int, float)) and not isinstance(record.get("ts"), bool) and "e" not in repr(record["ts"]):
                        record["ts_utc"] = epoch_to_iso(repr(record["ts"]))
                        if not record["ts_utc"]:
                            self.times_not_decoded += 1
                else:
                    cols = line.split(separator)
                    if self.header_problem:
                        self._flag(self.lines, start, self.header_problem, raw=line)
                        continue
                    if len(cols) != len(self.fields):
                        self._flag(self.lines, start, "%d columns, and the header names %d fields" % (len(cols), len(self.fields)), raw=line)
                        continue
                    types = self.types or ["string"] * len(self.fields)
                    record = {}
                    try:
                        for name, typ, value in zip(self.fields, types, cols):
                            record[name] = convert(value, typ, set_separator, empty, unset)
                            if typ == "time" and value != unset:
                                record[name + "_utc"] = epoch_to_iso(value)
                                if not record[name + "_utc"]:
                                    self.times_not_decoded += 1
                    except BadValue as exc:
                        self._flag(self.lines, start, "field %s: %s" % (name, exc), raw=line)
                        continue
                self.parsed += 1
                self.hook(self.stem, record, self)
                if len(self.records) < self.limit:
                    self.records.append(record)
        if self._bad is not None:
            self._bad.flush()
            os.fsync(self._bad.fileno())
            self._bad.close()


def withheld_text(length):
    return "<withheld %d characters>" % length


# A string that is an identifier, a hash, a fingerprint, an address or a time stays as written; every other string is
# scrubbed, since a record's free text (a notice's msg, a weird's addl, a file name, a header) can quote anything.
KEEP_FIELD = re.compile(r"(?i)^(ts|uid|fuid|uids|fuids|conn_uids|md5|sha1|sha256|ja3s?|ja4[a-z0-9_]*|hassh[a-z0-9_]*|community_id|proto|service|conn_state|"
                        r"history|level|id\.(orig|resp)_[hp]|[a-z_]*_h|[a-z_]*_p|[a-z_]*_utc)$")


def _scrub_value(value, withheld):
    if isinstance(value, str):
        if re.search(r"://|^//", value) or (value.startswith("/") and "?" in value):
            shown = redact_url(value)
            withheld["urls"] += 1 if shown != value else 0
        else:
            shown = scrub(value)
            withheld["text"] += 1 if shown != value else 0
        return shown
    if isinstance(value, list):
        return [_scrub_value(v, withheld) for v in value]
    return value


def inline_copy(stem, record, withheld):
    """The record as it may be returned inline: secret-named fields withheld, every other string scrubbed, URLs redacted."""
    out = {}
    pass_command = isinstance(record.get("command"), str) and record["command"].upper() == "PASS"
    short = None
    if stem == "files":
        sizes = [v for v in (record.get("total_bytes"), record.get("seen_bytes")) if isinstance(v, int)]
        short = bool(sizes) and min(sizes) < SHORT_OBJECT
    for key, value in record.items():
        if value is None or value == [] or value == "":
            out[key] = value
        elif SECRET_FIELD.search(key) or (pass_command and key == "arg"):
            out[key] = withheld_text(len(str(value)))
            withheld["fields"] += 1
        elif short and key in HASH_FIELDS:
            out[key] = "<withheld: the object is shorter than %d bytes>" % SHORT_OBJECT
            withheld["short_hashes"] += 1
        elif URL_FIELD.match(key) and isinstance(value, str):
            out[key] = redact_url(value)
            withheld["urls"] += 1
        elif KEEP_FIELD.match(key):
            out[key] = value
        else:
            out[key] = _scrub_value(value, withheld)
    return out


def main():
    started = time.monotonic()
    install_signal_handlers()
    try:
        args = json.load(sys.stdin)
    except ValueError as exc:
        fail("arguments are not valid JSON", reason=str(exc))
    if not isinstance(args, dict):
        fail("arguments must be a JSON object")
    path = args.get("path")
    if not isinstance(path, str) or not path:
        fail("path is required: a capture file")
    if not os.path.isfile(path):
        fail("no such file", path=path)
    out_dir = args.get("out_dir")
    if not isinstance(out_dir, str) or not out_dir:
        fail("out_dir is required: a directory under work/ (in a job, under $OUT) for Zeek's logs")
    out_dir = resolve_output(out_dir, "out_dir")
    try:
        if os.path.exists(out_dir) and os.listdir(out_dir):
            fail("out_dir already holds files; stale Zeek logs would contaminate the result", out_dir=out_dir)
    except OSError as exc:
        fail("out_dir cannot be listed (%s)" % describe(exc), out_dir=out_dir)
    limit = args.get("limit", 200)
    if not isinstance(limit, int) or isinstance(limit, bool) or limit < 1:
        fail("limit must be a positive integer")
    timeout = args.get("timeout_seconds", DEFAULT_TIMEOUT)
    if not isinstance(timeout, int) or isinstance(timeout, bool) or not 10 <= timeout <= MAX_TIMEOUT:
        fail("timeout_seconds must be an integer from 10 to %d: kept under the 1200-second limit so that this tool stops Zeek itself and the "
             "limit never has to" % MAX_TIMEOUT)
    wanted_arg = args.get("logs")
    if wanted_arg is not None and (not isinstance(wanted_arg, list) or any(not isinstance(n, str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", n) for n in wanted_arg)):
        fail("logs must be a list of log names such as [\"conn\", \"dns\"]")
    wanted = set(wanted_arg or [])
    policies = args.get("policies", DEFAULT_POLICIES)
    if not isinstance(policies, list) or any(not isinstance(p, str) for p in policies):
        fail("policies must be a list of Zeek policy names, such as policy/frameworks/files/hash-all-files")
    for name in policies:
        segments = name.split("/")
        if (not re.fullmatch(r"[A-Za-z0-9_./-]{1,200}", name) or name.startswith("/") or ".." in segments or "." in segments or "" in segments
                or segments[0] in ("inputs", "work", "store")):
            fail("a policy is a name Zeek resolves from its own script path, not a path or anything from the evidence: refused", policy=name)
    checksum_validation = args.get("checksum_validation", False)
    if not isinstance(checksum_validation, bool):
        fail("checksum_validation must be true or false")

    binary = shutil.which("zeek") or shutil.which("bro")
    if not binary:
        fail("zeek is not on PATH",
             install="brew install zeek, or the Zeek project's own packages "
                     "(https://software.opensuse.org/download.html?project=security%3Azeek&package=zeek): "
                     "zeek is in neither Debian's nor Ubuntu's archive",
             note="Without it, pcap_summary still answers the first questions about a "
                  "capture. Say in the report which route was taken.")
    os.umask(0o077)
    version_code, version_out, version_err, version_timed_out = preflight([binary, "--version"], min(30, timeout))
    version_text = (version_out + version_err).decode("utf-8", "replace").strip().splitlines()
    zeek_version = version_text[0].strip() if version_code == 0 and version_text else None

    try:
        os.makedirs(out_dir, mode=0o700, exist_ok=True)
        os.chmod(out_dir, 0o700)
    except OSError as exc:
        fail("the output directory could not be created (%s)" % describe(exc), out_dir=out_dir)
    script_path = script_sha = None
    argv = [binary]
    if not checksum_validation:
        argv.append("-C")
    argv += ["-r", os.path.abspath(path)]
    if policies:
        script_path = os.path.join(out_dir, SCRIPT_NAME)
        text = ("# Written by zeek_run (network-forensics pack): the policies the caller asked for, loaded explicitly.\n"
                + "".join("@load %s\n" % p for p in policies))
        try:
            fd = os.open(script_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(text)
        except OSError as exc:
            fail("the policy script could not be written (%s)" % describe(exc), out_dir=out_dir)
        script_sha = hashlib.sha256(text.encode("utf-8")).hexdigest()
        argv.append(os.path.abspath(script_path))
    stdout_path = os.path.join(out_dir, "zeek.stdout")
    stderr_path = os.path.join(out_dir, "zeek.stderr")
    try:
        code, timed_out = run_to_files(argv, stdout_path, stderr_path, timeout - (time.monotonic() - started), cwd=out_dir)
    except OSError as exc:
        fail("zeek could not be run (%s)" % describe(exc), command=argv)
    if timed_out:
        partial = sorted(n[:-4] for n in os.listdir(out_dir) if n.endswith(".log"))
        fail("zeek did not finish in time and was killed with everything it had started", after_seconds=timeout, command=argv,
             partial_output=out_dir, logs_written_so_far=partial, stdout=stdout_path, stderr=stderr_path)

    written = sorted(n for n in os.listdir(out_dir) if n.endswith(".log"))
    if not written:
        fail("zeek wrote no logs", exit_code=code, command=argv, stdout=stdout_path, stderr=stderr_path)
    for name in os.listdir(out_dir):
        try:
            os.chmod(os.path.join(out_dir, name), 0o700 if os.path.isdir(os.path.join(out_dir, name)) else 0o600)
        except OSError:
            pass

    withheld = {"fields": 0, "urls": 0, "text": 0, "short_hashes": 0}
    diagnostics = {"reporter": {"records": 0, "levels": {}, "first_messages": []},
                   "weird": {"records": 0, "by_name": {}, "names_over_cap": 0},
                   "capture_loss": {"records": 0, "gaps": 0, "acks": 0, "max_percent_lost": None}}
    files = {"records": 0, "records_with_a_hash": 0}

    def hook(stem, record, _reader):
        if stem == "reporter":
            d = diagnostics["reporter"]
            d["records"] += 1
            level = str(record.get("level"))
            d["levels"][level] = d["levels"].get(level, 0) + 1
            if len(d["first_messages"]) < 5:
                d["first_messages"].append(scrub(str(record.get("message", "")))[:500])
        elif stem == "weird":
            d = diagnostics["weird"]
            d["records"] += 1
            name = str(record.get("name"))
            if name in d["by_name"] or len(d["by_name"]) < MAX_NAMES:
                d["by_name"][name] = d["by_name"].get(name, 0) + 1
            else:
                d["names_over_cap"] += 1
        elif stem == "capture_loss":
            d = diagnostics["capture_loss"]
            d["records"] += 1
            for k in ("gaps", "acks"):
                if isinstance(record.get(k), int):
                    d[k] += record[k]
            pct = record.get("percent_lost")
            if isinstance(pct, (int, float)) and (d["max_percent_lost"] is None or pct > d["max_percent_lost"]):
                d["max_percent_lost"] = pct
        elif stem == "files":
            files["records"] += 1
            if any(record.get(h) not in (None, "", []) for h in HASH_FIELDS):
                files["records_with_a_hash"] += 1

    logs, problems, malformed, malformed_files, empty = {}, [], [], {}, []
    hash_fields = []
    total_malformed = 0
    times_not_decoded = 0
    for name in written:
        stem = name[:-4]
        log_path = os.path.join(out_dir, name)
        inline = (not wanted) or stem in wanted
        reader = LogReader(log_path, stem, limit if inline else 0, os.path.join(out_dir, "malformed-%s.jsonl" % re.sub(r"[^A-Za-z0-9_.-]", "_", stem)), hook)
        try:
            reader.read()
        except OSError as exc:
            problems.append({"log": stem, "why": describe(exc)})
            continue
        if stem == "files":
            hash_fields = [h for h in HASH_FIELDS if h in reader.hash_keys]
        times_not_decoded += reader.times_not_decoded
        total_malformed += reader.malformed_total
        if reader.malformed_total:
            malformed.extend(reader.malformed)
            malformed_files[stem] = "malformed-%s.jsonl" % re.sub(r"[^A-Za-z0-9_.-]", "_", stem)
        if reader.parsed == 0 and not reader.malformed_total:
            empty.append(stem)
        if inline:
            logs[stem] = {"file": log_path, "format": reader.format, "fields": reader.fields, "types": reader.types,
                          "records": [inline_copy(stem, r, withheld) for r in reader.records],
                          "returned": len(reader.records), "total": reader.parsed, "omitted": reader.parsed - len(reader.records),
                          "malformed": reader.malformed_total, "lines": reader.lines,
                          **({"header_problem": reader.header_problem} if reader.header_problem else {})}
    not_written = sorted(n for n in wanted if n + ".log" not in written)
    hashes_produced = files["records_with_a_hash"] > 0
    if zeek_version is None:
        problems.append({"why": "`zeek --version` %s, so the version of the engine that wrote these logs is not recorded" %
                         ("did not finish" if version_timed_out else "exited %s" % version_code)})
    ok = code == 0 and not problems and not total_malformed
    answer = {
        "tool": TOOL, "parser": PARSER,
        "path": path, "out_dir": out_dir,
        "zeek_version": zeek_version,
        "command": argv,
        "checksum_validation": checksum_validation,
        "checksum_note": ("checksums were validated" if checksum_validation else
                          "checksums were NOT validated (-C): a packet with a bad checksum, such as one captured on an offloading interface, "
                          "was processed like any other"),
        "policy": {"requested": policies, "script": script_path, "script_sha256": script_sha,
                   "note": ("no policy script was loaded: Zeek ran with its base scripts only" if not policies else
                            "the script loads the named policies explicitly; that it ran, and that the installed build has them, is shown by the logs "
                            "and by exit_code, not assumed")},
        "exit_code": code,
        "logs_written": [n[:-4] for n in written],
        "logs_requested_not_written": not_written,
        "logs_empty": empty,
        "logs": logs,
        "problems": problems,
        "malformed_records": total_malformed,
        "malformed": malformed,
        "malformed_files": malformed_files,
        "hashes_produced": hashes_produced,
        "hash_fields": hash_fields,
        "hash_note": ("hash_fields are the hash columns files.log has or its JSON records use; on a real install the columns can exist whether or not "
                      "any analyzer filled them, so only hashes_produced (a record with a value) says a hash exists, and which hash functions the "
                      "loaded policy computes is a property of the build"),
        "times_not_decoded": times_not_decoded,
        "files_log": {"written": "files.log" in written, "records": files["records"], "records_with_a_hash": files["records_with_a_hash"]},
        "engine_diagnostics": {**diagnostics,
                               "capture_loss_note": None if "capture_loss.log" in written else
                               "capture_loss.log was not written: Zeek writes it only when its capture-loss policy is loaded, so its absence says nothing about loss"},
        "withheld": {"inline_records": withheld, "shared_block": dict(COUNTS)},
        "stdout": stdout_path,
        "stderr": stderr_path,
        "ok": ok,
        "out_dir_contains_secret_values": True,
        "out_dir_note": ("Zeek's logs can carry credentials, cookies, community strings and request URIs, depending on the scripts loaded. The "
                         "directory is private (mode 0700, files 0600). Run this tool as a job with secret_output: true so the job output is "
                         "sealed. Inline records withhold secret-named fields and the hash of an object under 128 bytes, redact URLs, and scrub "
                         "every other string except identifiers, hashes, fingerprints, addresses and times (by shape: a short secret in free "
                         "text is not recognised); the log files themselves are whole."),
        "note": ("Each complete log is kept and named in its entry; inline records are bounded by limit, and omitted says how many were not returned. "
                 "conn.log's orig_bytes and resp_bytes count what Zeek saw each way for a connection as Zeek defines it (a connection with no "
                 "handshake, a UDP flow and a resumed one are all conn.log rows), not application data delivered. A hash in files.log exists only "
                 "if hash_fields names it and a record has a value: check hashes_produced, and where Zeek could not reassemble an object there is "
                 "none. Zeek's own stdout and stderr are kept beside the logs; reporter, weird and capture_loss are summarised under "
                 "engine_diagnostics."),
    }
    print(json.dumps(answer, indent=2))
    return 0 if ok else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except SystemExit:
        raise
    except BaseException as exc:  # noqa: BLE001 - never a traceback, never a clean answer for a failure
        fail("unexpected failure: %s" % describe(exc))
