#!/usr/bin/env python3
"""Normalise web, proxy and firewall logs into one table, and account for every line without printing a secret.

The grammars implemented, and no others:

    web       Apache or nginx access log, common or combined format ([day/Mon/year:time zone offset] ... "request")
    squid     Squid's native access.log (epoch seconds, elapsed, client, code/status, bytes, method, URL, user,
              hierarchy/peer, type)
    firewall  a line of upper-case KEY=VALUE pairs (SRC=, DST=, PROTO=, SPT=, DPT= ...), such as netfilter's log

A line that fits none of them is unparsed, and says so; a vendor format that is none of these is not parsed.

What the table holds. Every source line is in normalized.tsv or unparsed.tsv, and each row carries its physical line
number and the byte offset and length of the line in the stream that was read (the decompressed stream, for a gzip
file), so a row can be found in the evidence. The file is read as bytes: a line that is not valid UTF-8 is decoded
with substitution and counted (decoding_substituted), a CRLF is counted, a final line with no line end is said, and
a line longer than max_line_bytes is located and not read.

Time has three columns and no more meaning than each carries: timestamp_raw is the text as written (for a
firewall line, the whole prefix before the first KEY=VALUE, which holds the host and often the action as well);
timestamp_utc is filled only where the line itself gives enough to derive it (a web line has an offset, a Squid
line is epoch seconds, a firewall line may begin with an ISO 8601 time that has a zone) and is empty for a syslog
stamp, which has no year and no zone; timezone_source says which. Nothing is assumed to be UTC.

Nothing is cut and nothing is unbounded: gzip expansion is capped (max_expanded_bytes) and a cap that ends the read
is reported with the offset it ended at (complete: false, ok: false); a corrupt gzip stream is a structured error
that keeps the rows written before it and names the last good offset; aggregates hold at most max_distinct_values
distinct values per category, and the occurrences past that are counted (distinct_cap_reached).

SENSITIVE OUTPUT. A request target can carry credentials (user-info, tokens in the path or the query), and an
unparsed line can be anything. The target in the table is REDACTED: user-info, token-shaped path text and every
query value are withheld (the parameter names stay). The raw text of an unparsed line is not in unparsed.tsv, and no
raw line is in the answer. write_values: true (refused outside a job; created exclusively, mode 0600, before
anything is read) writes the unparsed lines' text and each redacted target's original to
$OUT/network-log-values.jsonl and nowhere else; a second run in the same job is refused by name. The directory is
private (mode 0700, files 0600): run the tool as a job with secret_output: true.
"""
import collections
import datetime
import errno
import gzip
import json
import os
import re
import sys
import zlib
from pathlib import Path

TOOL = {"name": "network_log_summary", "version": 4}
PARSER = "network_log_summary/4"
COLUMNS = ["line", "byte_offset", "byte_length", "format", "parse_status", "timestamp_raw", "timestamp_utc", "timezone_source",
           "src", "dst", "src_port", "dst_port", "protocol", "method", "target", "referer", "status", "bytes", "action", "user",
           "user_agent", "elapsed_ms", "hierarchy", "mime", "in_if", "out_if", "nat_src", "nat_dst", "tcp_flags", "decoding"]
UNPARSED_COLUMNS = ["line", "byte_offset", "byte_length", "parse_status", "reason", "decoding"]
DEFAULT_MAX_LINE = 1 << 20
DEFAULT_MAX_EXPANDED = 4 << 30
DEFAULT_MAX_DISTINCT = 200_000
MAX_KEY = 512                  # an aggregate key is cut here (counted); the table row has the whole value
WEB = re.compile(
    r'^(?P<src>\S+)\s+\S+\s+(?P<user>\S+)\s+\[(?P<time>[^]]+)\]\s+'
    r'"(?P<request>[^"]*)"\s+(?P<status>\S+)\s+(?P<bytes>\S+)'
    r'(?:\s+"(?P<ref>[^"]*)"\s+"(?P<ua>[^"]*)")?.*$')
KV = re.compile(r'\b([A-Z][A-Z0-9_]*)=("[^"]*"|\S*)')
WEB_TIME = re.compile(r"^(\d{1,2})/([A-Za-z]{3})/(\d{4}):(\d{2}):(\d{2}):(\d{2}) ([+-])(\d{2})(\d{2})$")
ISO_PREFIX = re.compile(r"^\s*(?:<\d{1,3}>\d\s+)?(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?(Z|[+-]\d{2}:?\d{2})(?=\s|$)")
MONTHS = {m: i for i, m in enumerate(("jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"), 1)}

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
    inputs are the one place the tables must never appear: a later integrity check would report the evidence as
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

    NAME = "network-log-values.jsonl"

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
                "file, not a sealed secret output. Run this as job_run tool=network_log_summary with "
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
            "format": ("JSON Lines, mode 0600: finding_id, line, byte_offset, byte_length, status, target and referer (the originals, for a redacted "
                       "one), value (the whole source line, as JSON escapes)") if self.enabled else None,
        }


def epoch_to_iso(text):
    m = re.fullmatch(r"(\d{1,12})(?:\.(\d{1,9}))?", text.strip())
    if not m:
        return ""
    try:
        stamp = datetime.datetime.fromtimestamp(int(m.group(1)), tz=datetime.timezone.utc)
    except (OverflowError, OSError, ValueError):
        return ""
    return stamp.strftime("%Y-%m-%dT%H:%M:%S") + ("." + m.group(2) if m.group(2) else "") + "Z"


def web_time(text):
    """A common-log time such as 14/Nov/2023:22:13:20 +0000 as ISO 8601 UTC; empty when it does not parse."""
    m = WEB_TIME.match(text.strip())
    if not m or m.group(2).lower() not in MONTHS:
        return ""
    day, mon, year, hh, mm, ss, sign, oh, om = m.groups()
    try:
        offset = datetime.timedelta(hours=int(oh), minutes=int(om)) * (1 if sign == "+" else -1)
        local = datetime.datetime(int(year), MONTHS[mon.lower()], int(day), int(hh), int(mm), int(ss), tzinfo=datetime.timezone(offset))
        return local.astimezone(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except (ValueError, OverflowError):
        return ""


def iso_to_utc(m):
    """An ISO 8601 time with a zone, matched by ISO_PREFIX, as UTC with its fraction digits kept; empty when it does not parse.
    Done by hand: the standard library's fromisoformat accepts different forms in different Python versions."""
    year, mon, day, hh, mm, ss, frac, zone = m.groups()
    try:
        sign = -1 if zone.startswith("-") else 1
        digits = zone.lstrip("Z+-").replace(":", "")
        offset = datetime.timedelta(hours=int(digits[:2] or 0), minutes=int(digits[2:] or 0)) * sign
        local = datetime.datetime(int(year), int(mon), int(day), int(hh), int(mm), int(ss), tzinfo=datetime.timezone(offset))
        return local.astimezone(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S") + ("." + frac if frac else "") + "Z"
    except (ValueError, OverflowError):
        return ""


def web(line):
    m = WEB.match(line)
    if not m:
        return None
    request = m.group("request").split()
    method = request[0] if request else ""
    target = request[1] if len(request) > 1 else ""
    derived = web_time(m.group("time"))
    if derived:
        source = "the offset written in the line"
    elif re.search(r" [+-]\d{4}$", m.group("time").strip()):
        source = "an offset is written but the date did not parse"
    else:
        source = "no zone offset is written in the line"
    ref = m.group("ref")
    return {"format": "web", "timestamp_raw": m.group("time"), "timestamp_utc": derived, "timezone_source": source,
            "src": m.group("src"), "method": method, "target": target, "referer": "" if ref in (None, "-") else ref, "status": m.group("status"),
            "bytes": "" if m.group("bytes") == "-" else m.group("bytes"),
            "user": "" if m.group("user") == "-" else m.group("user"), "user_agent": m.group("ua") or ""}


def squid(line):
    parts = line.split()
    if len(parts) < 9 or not re.fullmatch(r"\d+(?:\.\d+)?", parts[0]):
        return None
    if "/" not in parts[3] or not re.fullmatch(r"\d+", parts[4]):
        return None
    derived = epoch_to_iso(parts[0])
    return {"format": "squid", "timestamp_raw": parts[0], "timestamp_utc": derived,
            "timezone_source": "epoch seconds, which are UTC by definition" if derived else "epoch seconds out of range",
            "src": parts[2], "method": parts[5], "target": parts[6], "status": parts[3].split("/", 1)[1], "bytes": parts[4],
            "action": parts[3].split("/", 1)[0], "elapsed_ms": parts[1],
            "user": "" if parts[7] == "-" else parts[7], "hierarchy": parts[8], "mime": parts[9] if len(parts) > 9 else ""}


def firewall(line):
    pairs = {k: v.strip('"') for k, v in KV.findall(line)}
    if not pairs or not ({"SRC", "DST", "PROTO"} & set(pairs)):
        return None
    action = pairs.get("ACTION", "")
    if not action:
        for candidate in ("DROP", "REJECT", "ACCEPT", "ALLOW", "DENY", "BLOCK"):
            if re.search(r"(?:^|\s)%s(?:\s|$)" % candidate, line, re.I):
                action = candidate.upper()
                break
    first_kv = min((m.start() for m in KV.finditer(line)), default=0)
    flags = [flag for flag in ("SYN", "ACK", "FIN", "RST", "PSH", "URG", "ECE", "CWR") if re.search(r"(?:^|\s)%s(?:\s|$)" % flag, line, re.I)]
    prefix = line[:first_kv].strip()
    derived, source = "", "none in the line: a syslog stamp has no year and no zone"
    if not prefix:
        source = "no timestamp in the line"
    m = ISO_PREFIX.match(prefix)
    if m:
        derived = iso_to_utc(m)
        source = "the zone written in the line" if derived else "a zone is written but the time did not parse"

    def first(*names):
        return next((pairs[name] for name in names if pairs.get(name)), "")
    return {"format": "firewall", "timestamp_raw": prefix, "timestamp_utc": derived, "timezone_source": source,
            "src": pairs.get("SRC", ""), "dst": pairs.get("DST", ""),
            "src_port": pairs.get("SPT", pairs.get("SRC_PORT", "")), "dst_port": pairs.get("DPT", pairs.get("DST_PORT", "")),
            "protocol": pairs.get("PROTO", ""), "bytes": pairs.get("LEN", ""),
            "action": action, "in_if": pairs.get("IN", ""), "out_if": pairs.get("OUT", ""),
            "nat_src": first("NATSRC", "NAT_SRC", "ORIGSRC", "ORIG_SRC", "TRANS_SRC"),
            "nat_dst": first("NATDST", "NAT_DST", "ORIGDST", "ORIG_DST", "TRANS_DST"), "tcp_flags": ",".join(flags)}


def parse(line, wanted):
    parsers = {"web": web, "squid": squid, "firewall": firewall}
    if wanted != "auto":
        return parsers[wanted](line)
    for parser in (web, squid, firewall):
        found = parser(line)
        if found:
            return found
    return None


class ExpansionLimit(Exception):
    pass


class Source:
    """The log as a stream of bytes: plain, or gzip with a cap on what it may expand to."""

    def __init__(self, path, cap):
        with open(path, "rb") as fh:
            magic = fh.read(2)
        self.gzip = magic == b"\x1f\x8b"
        self.cap = cap
        self.fh = gzip.open(path, "rb") if self.gzip else open(path, "rb")
        self.read_total = 0

    def readline(self, limit):
        raw = self.fh.readline(limit)
        self.read_total += len(raw)
        if self.gzip and self.read_total > self.cap:
            raise ExpansionLimit()
        return raw

    def close(self):
        self.fh.close()


def optional_int(args, key, default, minimum):
    value = args.get(key, default)
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        fail("%s must be an integer of at least %d" % (key, minimum))
    return value


def main():
    try:
        args = json.load(sys.stdin)
    except ValueError as exc:
        fail("arguments are not valid JSON", reason=str(exc))
    if not isinstance(args, dict):
        fail("arguments must be a JSON object")
    path, out_dir = args.get("path"), args.get("out_dir")
    if not isinstance(path, str) or not os.path.isfile(path):
        fail("path must name a readable log file", path=path if isinstance(path, str) else None)
    if not isinstance(out_dir, str) or not out_dir:
        fail("out_dir is required: an empty directory under work/ (in a job, under $OUT)")
    out_dir = resolve_output(out_dir, "out_dir")
    try:
        if os.path.exists(out_dir) and os.listdir(out_dir):
            fail("out_dir already holds files", out_dir=out_dir)
    except OSError as exc:
        fail("out_dir cannot be listed (%s)" % describe(exc), out_dir=out_dir)
    wanted = str(args.get("format") or "auto").lower()
    if wanted not in ("auto", "web", "squid", "firewall"):
        fail("format must be auto, web, squid or firewall", format=wanted)
    top = optional_int(args, "top", 20, 1)
    max_line = optional_int(args, "max_line_bytes", DEFAULT_MAX_LINE, 4096)
    max_expanded = optional_int(args, "max_expanded_bytes", DEFAULT_MAX_EXPANDED, 1 << 20)
    max_distinct = optional_int(args, "max_distinct_values", DEFAULT_MAX_DISTINCT, 1)
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
            fail("the values file already exists", write_values="refused", written=False, values_file=os.path.join(os.environ["OUT"], SecretValues.NAME))

    os.umask(0o077)
    try:
        values = SecretValues(write_values)
    except SecretValuesRefused as exc:
        fail(str(exc), write_values="refused", written=False, values_file=exc.path)
    try:
        os.makedirs(out_dir, mode=0o700, exist_ok=True)
        os.chmod(out_dir, 0o700)
        source = Source(path, max_expanded)
    except (OSError, EOFError, zlib.error) as exc:
        values.discard()
        fail("the log or the output directory could not be opened (%s)" % describe(exc), out_dir=out_dir)
    normal_path, bad_path = os.path.join(out_dir, "normalized.tsv"), os.path.join(out_dir, "unparsed.tsv")
    categories = ("format", "src", "dst", "method", "status", "action")
    counts = {name: collections.Counter() for name in categories}
    over_cap = {name: 0 for name in categories}
    stats = {"lines": 0, "parsed": 0, "blank": 0, "unparsed_nonblank": 0, "over_limit": 0, "decoding_substituted": 0, "crlf_lines": 0,
             "timestamps_derived": 0, "timestamps_not_derived": 0, "bom_stripped": 0, "keys_cut": 0}
    zones = collections.Counter()
    unterminated = False
    read_error = None
    in_long_line = False
    offset = 0
    try:
        with open(normal_path, "x", encoding="utf-8", newline="\n") as normal, open(bad_path, "x", encoding="utf-8", newline="\n") as bad:
            normal.write("\t".join(COLUMNS) + "\n")
            bad.write("\t".join(UNPARSED_COLUMNS) + "\n")
            try:
                while True:
                    raw = source.readline(max_line + 1)
                    if not raw:
                        break
                    stats["lines"] += 1
                    number, start = stats["lines"], offset
                    if len(raw) > max_line and not raw.endswith(b"\n"):
                        length = len(raw)
                        in_long_line = True
                        while True:
                            more = source.readline(max_line)
                            length += len(more)
                            if not more or more.endswith(b"\n"):
                                break
                        offset += length
                        in_long_line = False
                        stats["over_limit"] += 1
                        bad.write("\t".join(cell(v) for v in (number, start, length, "line_over_limit", "longer than max_line_bytes (%d): located, not read" % max_line, "not read")) + "\n")
                        continue
                    offset += len(raw)
                    terminated = raw.endswith(b"\n")
                    unterminated = not terminated
                    body = raw[:-1] if terminated else raw
                    if number == 1 and body.startswith(b"\xef\xbb\xbf"):
                        body = body[3:]
                        stats["bom_stripped"] += 1
                    if body.endswith(b"\r"):
                        body = body[:-1]
                        stats["crlf_lines"] += 1
                    try:
                        line = body.decode("utf-8")
                        decoding = "exact"
                    except UnicodeDecodeError:
                        line = body.decode("utf-8", "replace")
                        decoding = "substituted"
                        stats["decoding_substituted"] += 1
                    if not line.strip():
                        stats["blank"] += 1
                        bad.write("\t".join(cell(v) for v in (number, start, len(raw), "blank", "an empty line", decoding)) + "\n")
                        continue
                    row = parse(line, wanted)
                    if row is None:
                        stats["unparsed_nonblank"] += 1
                        bad.write("\t".join(cell(v) for v in (number, start, len(raw), "unparsed", "no grammar of the requested format matched", decoding)) + "\n")
                        values.add("L%06d" % number, {"line": number, "byte_offset": start, "byte_length": len(raw), "status": "unparsed"},
                                   body.decode("utf-8", "surrogateescape"))
                        continue
                    stats["parsed"] += 1
                    original, original_referer = row.get("target", ""), row.get("referer", "")
                    row["target"] = redact_url(original) if original else ""
                    row["referer"] = redact_url(original_referer) if original_referer else ""
                    changed = row["target"] != original or row["referer"] != original_referer
                    for key in ("method", "status", "user", "user_agent", "protocol", "action", "hierarchy", "mime", "bytes", "in_if", "out_if"):
                        if row.get(key):
                            shown = scrub(row[key])
                            changed = changed or shown != row[key]
                            row[key] = shown
                    if changed:
                        values.add("L%06d" % number, {"line": number, "byte_offset": start, "byte_length": len(raw), "status": "parsed",
                                                       "target": original, "referer": original_referer}, body.decode("utf-8", "surrogateescape"))
                    if row.get("timestamp_utc"):
                        stats["timestamps_derived"] += 1
                    else:
                        stats["timestamps_not_derived"] += 1
                    zones[row.get("timezone_source", "")] += 1
                    row.update(line=number, byte_offset=start, byte_length=len(raw), parse_status="parsed", decoding=decoding)
                    normal.write("\t".join(cell(row.get(column, "")) for column in COLUMNS) + "\n")
                    for name in categories:
                        if row.get(name):
                            key = str(row[name])
                            if len(key) > MAX_KEY:
                                key = key[:MAX_KEY] + "...(+%d characters)" % (len(key) - MAX_KEY)
                                stats["keys_cut"] += 1
                            if key in counts[name] or len(counts[name]) < max_distinct:
                                counts[name][key] += 1
                            else:
                                over_cap[name] += 1
            except ExpansionLimit:
                read_error = {"error": "expansion_limit", "message": "the decompressed stream passed max_expanded_bytes (%d)" % max_expanded,
                              "last_complete_line": stats["lines"] - (1 if in_long_line else 0), "stream_offset": offset}
            except (OSError, EOFError, zlib.error) as exc:
                read_error = {"error": type(exc).__name__, "message": describe(exc),
                              "last_complete_line": stats["lines"] - (1 if in_long_line else 0), "stream_offset": offset}
            normal.flush()
            os.fsync(normal.fileno())
            bad.flush()
            os.fsync(bad.fileno())
    except OSError as exc:
        values.discard()
        fail("a table could not be written (%s)" % describe(exc), out_dir=out_dir)
    finally:
        source.close()
        values.close()
    for name in os.listdir(out_dir):
        try:
            os.chmod(os.path.join(out_dir, name), 0o600)
        except OSError:
            pass

    def leading(counter):
        return [{"value": value, "count": count} for value, count in counter.most_common(top)]
    complete = read_error is None
    if not complete:
        values.discard()
    answer = {
        "tool": TOOL, "parser": PARSER,
        "path": path, "format_requested": wanted, "compression": "gzip" if source.gzip else "none",
        "offsets_are_in": "the decompressed stream" if source.gzip else "the file",
        "lines": stats["lines"], "parsed": stats["parsed"], "unparsed": stats["lines"] - stats["parsed"], "blank": stats["blank"],
        "unparsed_not_blank": stats["unparsed_nonblank"], "lines_over_limit": stats["over_limit"], "max_line_bytes": max_line,
        "decoding_substituted": stats["decoding_substituted"], "crlf_lines": stats["crlf_lines"],
        "last_line_has_no_line_end": unterminated,
        "timestamps": {"derived": stats["timestamps_derived"], "not_derived": stats["timestamps_not_derived"], "timezone_sources": dict(zones)},
        "normalized_tsv": normal_path, "unparsed_tsv": bad_path,
        "aggregate": {name: leading(counter) for name, counter in counts.items()},
        "distinct_cap_reached": {name: n for name, n in over_cap.items() if n} or None,
        "aggregate_keys_cut": stats["keys_cut"], "bom_stripped": stats["bom_stripped"],
        "aggregate_note": "a ranking is exact only while distinct_cap_reached is null: once a category holds max_distinct_values values, a value first seen later is counted in distinct_cap_reached and never in the ranking",
        "max_distinct_values": max_distinct,
        "complete": complete, "read_error": read_error,
        "ok": complete,
        "withheld": dict(COUNTS),
        "secret_values": values.summary(),
        "out_dir_contains_secret_values": True,
        "out_dir_note": ("The tables carry redacted targets and no raw line, and the directory is private (mode 0700, files 0600). Redaction is by shape: "
                         "user-info, token-shaped path text and every query value are withheld, and the text of an unparsed line is not in "
                         "unparsed.tsv; a secret that does not look like a token (a short password in a path segment, a user column) is not recognised, "
                         "so run the tool as a job with secret_output: true. write_values: true (jobs only) writes the originals to one 0600 file."),
        "note": ("Every source line is in normalized.tsv or unparsed.tsv with its line number, byte offset and byte length; the answer holds no raw line. "
                 "Aggregates are bounded by top. timestamp_utc is filled only where the line gives enough to derive it, and timezone_source says how; a "
                 "syslog stamp has no year and no zone and is never read as UTC. A forwarded-for header, a NAT address and an action label are what the "
                 "logging device wrote, not facts about the host that sent the traffic."),
    }
    if not complete:
        answer["note"] = "THE READ STOPPED EARLY (read_error): what is in the tables is what was read before it. " + answer["note"]
    print(json.dumps(answer, indent=2))
    return 0 if complete else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except SystemExit:
        raise
    except BaseException as exc:  # noqa: BLE001 - never a traceback, never a clean answer for a failure
        fail("unexpected failure: %s" % describe(exc))
