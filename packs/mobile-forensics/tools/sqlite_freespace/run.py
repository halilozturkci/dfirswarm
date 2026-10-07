#!/usr/bin/env python3
"""Text fragments from the space a SQLite database's main file no longer uses.

Deleting a row does not erase it. SQLite marks the space free and the bytes stay in the page
until the page is reused; whole pages go on a freelist and keep their contents. This reads
three kinds of free space in the main database file:

    freelist pages          a trunk page after its leaf-pointer array, and every leaf page
    the unallocated gap     of an in-use b-tree page, between the cell pointer array and the
                            first cell
    freeblocks              the chain of freed cells inside a b-tree page's cell content area,
                            where a deleted row's own bytes usually sit

WHAT COMES BACK IS TEXT, NOT ROWS. A fragment has no guaranteed column, no guaranteed table
and no reliable time: the page may have belonged to another table, and SQLite overwrites the
first four bytes of a freed cell with the freeblock header. A negative covers only the regions
examined and the encodings below. It says nothing about a -wal or a -journal, which this tool
lists and does not read, nor about a database that was vacuumed or created with secure_delete.

Encodings. UTF-8 text (ASCII, and the multi-byte sequences of any language) and UTF-16LE text
(ASCII range, Latin, Greek, Cyrillic, Hebrew, Arabic, common punctuation, and, as a lower
confidence reading that needs a longer run, CJK, kana, Hangul and emoji), read at either byte
parity because a text can start on any byte. A database that declares UTF-16BE is read as UTF-16BE
instead of UTF-16LE (a text read in the other byte order at the other parity is the same letters). A UTF-16 candidate whose bytes are mostly in a run already taken (printable ASCII read
at the wrong parity is a run of CJK units) is not reported. Text in any other encoding, in a
binary column or in a compressed or encrypted value is not found: absence of a hit is not
absence of the content.

Every offset is the byte position in the file, and every reported fragment was read back from
the file at that offset and compared with what was found before it was reported.

THE SECRET-SAFE OUTPUT PATTERN. A free page of a messenger's database holds message text, and
sometimes a credential. The answer carries the page, the kind of region, the offset, the length
and the encoding of each fragment, and never its text. The text is written only on
`write_values: true`, in a job run with `secret_output: true`, to a 0600 file under $OUT that
the answer names (the shared block below has the rules).

The file is read-only to this tool: it is opened for reading, as bytes, and never written.
"""
import errno
import hashlib
import json
import math
import os
import re
import signal
import struct
import sys
import tempfile
import time
from pathlib import Path

PARSER = "sqlite_freespace/2"
TOOL = "sqlite_freespace"
VALUES_NAME = "sqlite-freespace-values.jsonl"
VALUES_FORMAT = ("JSON Lines, mode 0600: finding_id, file (the real path), page, where, encoding, "
                 "offset, bytes, characters, value (the fragment's text, whole)")


# --- shared with the pack's other tools: begin ---------------------------------------------
# The three tools of this pack carry this block byte for byte (a test holds the copies equal),
# so that they withhold the same strings, write the same files the same way and refuse in the
# same words. Standalone tools do not import each other: the block is copied.
#
# THE SECRET-SAFE OUTPUT PATTERN (docs/packs.md, "Secrets and sensitive output"), as the
# encrypted-containers pack's recovery_key_scan introduced it and the macOS pack's plist_read
# copied it:
#   1. The answer carries presence, kind, location (file and offset or path), length and counts.
#      It carries no value, no characters of one, no masked shape and no digest of one.
#   2. A value is written only on `write_values: true`, only when the tool runs as a job
#      (JOB_ID and OUT are set), and only to a file under $OUT: JSON Lines, mode 0600, created
#      exclusively before anything is read. The skill that sends the agent here says the job runs
#      with `secret_output: true`. Outside a job the request is refused and nothing is written.
#   3. A secret is never on a command line: these tools take a path and flags only.
#   4. A printed path component shaped like a recovery password is withheld on every output
#      channel (the answer, the files it names, an error message); the values file keeps the
#      real path.

WITHHELD = "<recovery-password-shaped name withheld>"
PATHS_WITHHELD = [0]
# A BitLocker recovery password is eight groups of six digits. A file or a directory named after
# one (people save a key under its own name) would print it in every row that names the file.
RECOVERY = re.compile(rb"(?<![0-9])(\d{6})-(\d{6})-(\d{6})-(\d{6})-(\d{6})-(\d{6})-(\d{6})-(\d{6})(?![0-9])")
RECOVERY_UTF16LE = re.compile(
    rb"(?<![0-9]\x00)" + (rb"-\x00".join([rb"((?:[0-9]\x00){6})"] * 8)) + rb"(?![0-9]\x00)"
)
RECOVERY_TEXT = re.compile(RECOVERY.pattern.decode("ascii"))


def shown(path, count=True):
    """A path as it may be printed: any component shaped like a recovery password is withheld."""
    if not isinstance(path, str):
        return path
    parts = path.split("/")
    for i, part in enumerate(parts):
        if RECOVERY.search(part.encode("utf-8", "replace")) or RECOVERY_UTF16LE.search(part.encode("utf-16-le", "replace")):
            parts[i] = WITHHELD
            if count:
                PATHS_WITHHELD[0] += 1
    return "/".join(parts)


def scrub(text):
    """Text that may quote a path, with anything shaped like a recovery password withheld."""
    return RECOVERY_TEXT.sub(WITHHELD, text)


def describe(exc):
    code = errno.errorcode.get(exc.errno, "") if getattr(exc, "errno", None) else ""
    return scrub("%s%s: %s" % (type(exc).__name__, " " + code if code else "", getattr(exc, "strerror", None) or str(exc)))


def clean(value):
    """The value as strict JSON: a float that is not finite (JSON has no NaN or Infinity) is its text."""
    if isinstance(value, float) and not math.isfinite(value):
        return {"_float": repr(value)}
    if isinstance(value, dict):
        return {k: clean(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [clean(v) for v in value]
    return value


def dumps(value, **kwargs):
    return json.dumps(clean(value), allow_nan=False, default=str, **kwargs)


# What is open when a run fails: the pages and the values file are closed and named in the error, so a
# result read before the failure is kept, whole, and never left as a hidden temporary file.
OPEN_PAGES = []
OPEN_VALUES = []
NONCE = "%d-%d" % (os.getpid(), time.time_ns())


def fail(message, **extra):
    kept = []
    for page in OPEN_PAGES:
        if page._out is not None:
            try:
                kept.append(page.finish().get("all_results"))
            except Exception:
                pass
    answer = {"error": scrub(str(message)), **{k: (scrub(v) if isinstance(v, str) else v) for k, v in extra.items()}}
    if kept:
        answer["rows_read_before_the_failure_kept_in"] = kept
    for values in OPEN_VALUES:
        values.close()
        if values.written:
            answer["values_written_before_the_failure"] = {"file": values.shown, "rows": values.written}
    print(dumps(answer))
    raise SystemExit(1)


class Timeout(Exception):
    pass


def alarm_handler(signum, frame):
    raise Timeout()


def timed_search(pattern, text, seconds):
    """pattern.search(text), stopped after `seconds` where the platform can: a pattern the caller
    wrote can backtrack without end."""
    if not hasattr(signal, "setitimer"):
        return pattern.search(text)
    old = signal.signal(signal.SIGALRM, alarm_handler)
    signal.setitimer(signal.ITIMER_REAL, seconds)
    try:
        return pattern.search(text)
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, old)


def safe_name(text):
    return re.sub(r"[^A-Za-z0-9_.-]", "_", text)


class LosslessPage:
    """A page an agent reads, and the whole result in a file the answer names.

    The page stays small (rows, and bytes when a byte limit is given); when there are more rows
    the whole result is written as JSON Lines under work/<agent>/tool-output (in a job,
    $OUT/tool-output) and named: nothing is cut. The file name is a digest of the page's key (a
    path), never of a value. Rows are written with ensure_ascii on: a path the filesystem gave as
    bytes that are not UTF-8 reaches Python as lone surrogates, which a UTF-8 file cannot hold
    and an escape can. A rerun that would replace a larger earlier file of the same name writes a
    new name and says which earlier file it kept.
    """

    def __init__(self, tool, key, limit, byte_limit=None):
        if isinstance(limit, bool) or not isinstance(limit, int) or limit < 1:
            raise ValueError("limit must be a positive integer")
        self.tool = safe_name(tool)
        self.limit = limit
        self.byte_limit = byte_limit
        self.page = []
        self.page_bytes = 0
        self.full = False
        self.bytes_bound_hit = False
        self.total = 0
        self._out = None
        self._tmp = None
        OPEN_PAGES.append(self)
        # The key is the question (a path as it may be printed, a filter), plus this call's own nonce: two
        # questions that print alike (two files in directories whose names are withheld, two messages passed
        # in the call) never share a file, and a rerun never replaces an earlier result.
        digest = hashlib.sha256(dumps([key, NONCE], sort_keys=True).encode("utf-8")).hexdigest()[:16]
        name = "%s-%s.jsonl" % (self.tool, digest)
        job, out = os.environ.get("JOB_ID"), os.environ.get("OUT")
        if job and out:
            # In a job only $OUT is written, and it is sealed as the job's output: the whole
            # result is cited from there.
            self.path = Path(out) / "tool-output" / name
            self.shown = "store/jobs/%s/out/tool-output/%s" % (safe_name(job), name)
        else:
            agent = safe_name(os.environ.get("AGENT_ID") or "tool")
            self.path = Path("work") / agent / "tool-output" / name
            self.shown = str(self.path)

    def _write(self, row):
        self._out.write(dumps(row))
        self._out.write("\n")

    def add(self, row):
        self.total += 1
        if not self.full and len(self.page) < self.limit:
            size = len(dumps(row)) if self.byte_limit is not None else 0
            if self.byte_limit is None or self.page_bytes + size <= self.byte_limit:
                self.page.append(row)
                self.page_bytes += size
                return
            self.bytes_bound_hit = True
        # From the first row that does not fit, every later row goes to the file only: the page
        # is a prefix.
        self.full = True
        if self._out is None:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            fd, name = tempfile.mkstemp(dir=self.path.parent, prefix=".%s-" % self.path.name)
            self._tmp = Path(name)
            self._out = os.fdopen(fd, "w", encoding="utf-8")
            for kept in self.page:
                self._write(kept)
        self._write(row)

    def finish(self):
        result = {"matched": self.total, "returned": len(self.page), "truncated": self.total > len(self.page)}
        if self.byte_limit is not None:
            result["inline_byte_limit"] = self.byte_limit
            if self.bytes_bound_hit:
                result["inline_bounded_by_bytes"] = True
        if self._out is not None:
            self._out.flush()
            os.fsync(self._out.fileno())
            self._out.close()
            target, shown_as = self.path, self.shown
            if target.exists() and target.stat().st_size > os.path.getsize(self._tmp):
                n = 2
                while target.with_name("%s-%d%s" % (target.stem, n, target.suffix)).exists():
                    n += 1
                target = target.with_name("%s-%d%s" % (target.stem, n, target.suffix))
                shown_as = self.shown.rsplit("/", 1)[0] + "/" + target.name
                result["kept_earlier_larger_result"] = self.shown
            os.replace(self._tmp, target)
            result["all_results"] = shown_as
            result["all_results_format"] = "JSON Lines, one complete result per line"
        return result


class SecretValuesRefused(Exception):
    pass


class SecretValues:
    """Where a value goes when, and only when, the caller asked for it.

    The pattern of recovery_key_scan (encrypted-containers), copied: call `add` once per finding
    with its id, its locator and the value. With `enabled` false it writes nothing and
    `summary()` says so.
    """

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
                "file, not a sealed secret output. Run this as job_run tool=%s with "
                "secret_output: true, and ask again there. Nothing was written." % TOOL
            )
        self.path = Path(self.out) / VALUES_NAME
        self.shown = "store/jobs/%s/out/%s" % (safe_name(self.job), VALUES_NAME)
        # Created now, before anything is read: a file or a link already at that name is refused
        # by name at once (O_EXCL does not follow a link, a dangling one included), instead of
        # failing, or writing through it, after the scan. With nothing found it stays an empty
        # file, mode 0600, and the answer says written: 0.
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            fd = os.open(str(self.path), os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        except FileExistsError:
            raise SecretValuesRefused("the values file already exists: %s" % self.path)
        except OSError as exc:
            raise SecretValuesRefused("the values file could not be created: %s (%s)" % (self.path, describe(exc)))
        self._fh = os.fdopen(fd, "w", encoding="utf-8")
        OPEN_VALUES.append(self)

    def add(self, finding_id, locator, value):
        if not self.enabled:
            return
        # ensure_ascii: a file name that is not UTF-8 is a lone surrogate to Python; an escape
        # reads back, a raw write cannot.
        self._fh.write(dumps({"finding_id": finding_id, **locator, "value": value}))
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
            "format": VALUES_FORMAT if self.enabled else None,
        }


def open_values(args):
    """The values file, or a refusal as JSON: write_values must be true or false."""
    wanted = args.get("write_values", False)
    if not isinstance(wanted, bool):
        fail("write_values must be true or false")
    try:
        return SecretValues(wanted)
    except SecretValuesRefused as exc:
        fail(str(exc), write_values="refused", written=False)


def positive(args, name, default, maximum=None):
    value = args.get(name, default)
    if not isinstance(value, int) or isinstance(value, bool) or value < 1:
        fail("%s must be a positive integer" % name, **{name: value})
    if maximum is not None and value > maximum:
        fail("%s is at most %d" % (name, maximum), **{name: value})
    return value


def seconds(args, name, default, cap):
    """A time limit: finite, positive and at most `cap` (the tool's own limit less a margin, so that the
    answer is written before the harness stops the tool; NaN and Infinity would switch the clock off)."""
    value = args.get(name, default)
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value <= 0:
        fail("%s must be a positive finite number of seconds" % name, **{name: str(value)})
    if value > cap:
        fail("%s is at most %s seconds (the tool's own limit less the margin it needs to write its answer)" % (name, cap), **{name: value})
    return float(value)


def read_args():
    try:
        args = json.load(sys.stdin)
    except ValueError as exc:
        fail("arguments are not valid JSON", reason=str(exc))
    if not isinstance(args, dict):
        fail("arguments must be a JSON object")
    return args


def send(result):
    print(dumps(result, indent=2))


def run_main(main):
    try:
        main()
    except SystemExit:
        raise
    except Exception as exc:  # never an empty or clean answer for a failure, and never a traceback
        fail("unexpected failure: " + (describe(exc) if isinstance(exc, OSError) else "%s: %s" % (type(exc).__name__, exc)))
# --- shared with the pack's other tools: end -----------------------------------------------

MAGIC = b"SQLite format 3\x00"
LOCK_BYTE_OFFSET = 1 << 30
DEFAULT_LIMIT = 200
DEFAULT_MAX_SECONDS = 240
MAX_SECONDS_CAP = 270       # manifest.json timeout_seconds (300) less the time to write the answer
INLINE_BYTES = 1 << 20
REGEX_SECONDS = 2.0
PROBLEMS_INLINE = 200
TEXT_ENCODINGS = {1: "UTF-8", 2: "UTF-16LE", 3: "UTF-16BE"}
WIDE_MINIMUM = 8

# One character of UTF-8 text: printable ASCII with tab and the line ends, or a well-formed
# multi-byte sequence (no overlong form, no surrogate, no C1 control).
UTF8_CHAR = (rb"(?:[\x09\x0a\x0d\x20-\x7e]|\xc2[\xa0-\xbf]|[\xc3-\xdf][\x80-\xbf]"
             rb"|\xe0[\xa0-\xbf][\x80-\xbf]|[\xe1-\xec\xee\xef][\x80-\xbf]{2}|\xed[\x80-\x9f][\x80-\xbf]"
             rb"|\xf0[\x90-\xbf][\x80-\xbf]{2}|[\xf1-\xf3][\x80-\xbf]{3}|\xf4[\x80-\x8f][\x80-\xbf]{2})")

# UTF-16 text is found one code unit at a time, at either parity (a text can start on any byte). A unit is
# two bytes; the HIGH byte says which Unicode block it can be in and the LOW byte which characters of that
# block are accepted. Both bytes are translated to letters (upper case for a high byte, lower case for a
# low one) and a run is a regular expression over the interleaved letters, so a run can only start on a
# unit boundary of the parity being read. NARROW blocks are scripts whose byte pairs are rarely met in
# binary data; WIDE blocks (CJK, kana, Hangul, fullwidth forms, surrogate pairs for emoji) are met in
# random bytes about as often as in text, so a run that holds one has to be longer to be reported.
_ALL = range(256)
_BLOCKS = [  # (letter, high bytes, accepted low bytes, wide)
    ("A", [0x00], [0x09, 0x0a, 0x0d, *range(0x20, 0x7f), *range(0xa0, 0x100)], False),   # ASCII, Latin-1
    ("B", [0x01], _ALL, False),                                                            # Latin Extended-A
    ("C", [0x02], range(0x00, 0x50), False),                                               # Latin Extended-B, IPA
    ("D", [0x03], range(0x70, 0x100), False),                                              # Greek
    ("E", [0x04], _ALL, False),                                                            # Cyrillic
    ("F", [0x05], range(0x31, 0x100), False),                                              # Armenian, Hebrew
    ("G", [0x06], _ALL, False),                                                            # Arabic
    ("H", [0x20], [0x13, 0x14, 0x18, 0x19, 0x1c, 0x1d, 0x22, 0x26, 0xac], False),          # common punctuation, bullet, euro
    ("I", [0x09], range(0x00, 0x80), False),                                               # Devanagari
    ("J", [0x0e], range(0x01, 0x80), False),                                               # Thai
    ("K", [0x10, 0x1e, 0x1f], _ALL, False),                                                # Georgian, Latin Additional, Greek Extended
    ("W", [0x30, *range(0x4e, 0xa0), *range(0xac, 0xd8)], _ALL, True),                     # kana, ideographs, Hangul
    ("X", [0xff], range(0x00, 0xf0), True),                                                # fullwidth forms
    ("U", range(0xd8, 0xdc), _ALL, True),                                                  # high surrogate
    ("V", range(0xdc, 0xe0), _ALL, True),                                                  # low surrogate
]
HIGH_TABLE = bytearray(b"Z" * 256)
for _letter, _highs, _lows, _wide in _BLOCKS:
    for _h in _highs:
        HIGH_TABLE[_h] = ord(_letter)
HIGH_TABLE = bytes(HIGH_TABLE)
_signature = {b: tuple(b in set(lows) for _l, _h, lows, _w in _BLOCKS) for b in range(256)}
_letters = {}
for _b in range(256):
    _letters.setdefault(_signature[_b], chr(ord("a") + len(_letters)))
LOW_TABLE = bytes(ord(_letters[_signature[_b]]) for _b in range(256))
assert len(_letters) <= 26
_ACCEPT = {}
for _i, (_letter, _h, _lows, _w) in enumerate(_BLOCKS):
    _ACCEPT[_letter] = "".join(sorted({_letters[_signature[_b]] for _b in range(256) if _signature[_b][_i]}))
_UNIT = "|".join("%s[%s]" % (_l, _ACCEPT[_l]) for _l, _h, _lo, _w in _BLOCKS if _l not in "UV")
_UNIT += "|U[a-z]V[a-z]"
WIDE_LETTERS = re.compile(rb"[WXUV]")


def compile_runs(minimum):
    count = b"{%d,}" % minimum
    return {
        "utf-8": re.compile(b"(?:" + UTF8_CHAR + b")" + count),
        "utf-16": re.compile(("(?:" + _UNIT + "){%d,}" % minimum).encode("ascii")),
    }


def tokens(region, parity, little):
    """The units of `region` read from byte `parity`, as interleaved letters (high class, low class)."""
    data = region[parity:]
    n = len(data) // 2
    if n == 0:
        return b""
    pairs = data[:2 * n]
    low, high = (pairs[0::2], pairs[1::2]) if little else (pairs[1::2], pairs[0::2])
    out = bytearray(2 * n)
    out[0::2] = high.translate(HIGH_TABLE)
    out[1::2] = low.translate(LOW_TABLE)
    return bytes(out)


class OutOfTime(Exception):
    pass


def decode(raw, encoding):
    if encoding == "utf-8":
        return raw.decode("utf-8", "replace")
    return raw.decode("utf-16-le" if encoding == "utf-16le" else "utf-16-be", "replace")


def covered_by(accepted, start, end):
    inside = sum(max(0, min(end, e) - max(start, s)) for s, e in accepted)
    return inside * 2 >= end - start


def runs_in(region, patterns, encodings, wide_minimum):
    """(start, end, encoding) of the text runs in `region`, and how many candidates were dropped.

    UTF-8 runs are taken first. A UTF-16 run is then taken when it is at least minimum units (a run that
    holds a wide unit must be wide_minimum), narrow runs before wide ones, and is dropped when half or more
    of its bytes are already in a run taken: printable ASCII read at the wrong parity is a run of wide
    units, and a UTF-8 text read as UTF-16 is the same.
    """
    found, accepted = [], []
    for run in patterns["utf-8"].finditer(region):
        found.append((run.start(), run.end(), "utf-8"))
        accepted.append((run.start(), run.end()))
    narrow, wide = [], []
    for encoding in encodings:
        for parity in (0, 1):
            letters = tokens(region, parity, encoding == "utf-16le")
            for run in patterns["utf-16"].finditer(letters):
                start, end = parity + run.start(), parity + run.end()
                candidate = (start, end, encoding)
                if WIDE_LETTERS.search(letters[run.start():run.end():2]):
                    if (run.end() - run.start()) // 2 >= wide_minimum:
                        wide.append(candidate)
                else:
                    narrow.append(candidate)
    dropped = 0
    for candidate in sorted(narrow) + sorted(wide):
        if covered_by(accepted, candidate[0], candidate[1]):
            dropped += 1
            continue
        found.append(candidate)
        accepted.append((candidate[0], candidate[1]))
    found.sort(key=lambda f: (f[0], f[2]))
    return found, dropped


# Problems that say the file's structure disagrees with itself. Any of them makes the status `corrupt`
# (the fragments found are still reported); a limit or a page or file not examined makes it `partial`.
CORRUPT_KINDS = {
    "file shorter than its header says", "partial last page", "freelist cycle", "freelist page outside the file",
    "freelist trunk page truncated", "freelist trunk count too large", "freelist page listed twice",
    "freelist count differs from the header", "b-tree page header inconsistent", "freeblock chain corrupt",
    "fragment not found at its offset",
}


class Problems:
    """What was not examined, or does not add up, each with where: a guard that stopped a walk is
    said, never silent."""

    def __init__(self, page):
        self.page = page
        self.unexamined = 0
        self.kinds = {}

    def add(self, kind, detail, examined, **where):
        self.kinds[kind] = self.kinds.get(kind, 0) + 1
        if not examined:
            self.unexamined += 1
        self.page.add({"kind": kind, "detail": detail, "region_or_page_examined": examined, **where})


def entropy(data):
    """Bits per byte of a sample of at least 256 bytes; None for a shorter one (its statistics are its content)."""
    if len(data) < 256:
        return None
    counts = [0] * 256
    for byte in data:
        counts[byte] += 1
    return -sum(c / len(data) * math.log2(c / len(data)) for c in counts if c)


def header_of(head):
    page_size = struct.unpack_from(">H", head, 16)[0]
    if page_size == 1:
        page_size = 65536
    info = {
        "page_size": page_size,
        "write_version": head[18], "read_version": head[19], "reserved_bytes": head[20],
        "payload_fractions": [head[21], head[22], head[23]],
        "change_counter": struct.unpack_from(">I", head, 24)[0],
        "pages_declared": struct.unpack_from(">I", head, 28)[0],
        "freelist_head": struct.unpack_from(">I", head, 32)[0],
        "freelist_declared": struct.unpack_from(">I", head, 36)[0],
        "largest_root": struct.unpack_from(">I", head, 52)[0],
        "text_encoding": struct.unpack_from(">I", head, 56)[0],
        "user_version": struct.unpack_from(">I", head, 60)[0],
        "application_id": struct.unpack_from(">I", head, 68)[0],
        "version_valid_for": struct.unpack_from(">I", head, 92)[0],
        "sqlite_version_number": struct.unpack_from(">I", head, 96)[0],
    }
    info["usable_size"] = page_size - info["reserved_bytes"]
    info["declared_size_valid"] = info["pages_declared"] != 0 and info["change_counter"] == info["version_valid_for"]
    return info


def main():
    started = time.monotonic()
    args = read_args()
    db = args.get("db")
    if not isinstance(db, str) or not db:
        fail("db is required: a SQLite database file")
    if not os.path.isfile(db):
        fail("no such file", db=shown(db, False))
    minimum = args.get("min_length", 6)
    if not isinstance(minimum, int) or isinstance(minimum, bool) or minimum < 3:
        fail("min_length must be an integer of at least 3")
    contains = args.get("contains")
    pattern = None
    if contains:
        if not isinstance(contains, str) or len(contains) > 1000:
            fail("contains must be a regular expression of at most 1000 characters")
        try:
            pattern = re.compile(contains, re.I)
        except re.error as exc:
            fail("contains is not a valid regex", reason=str(exc))
    limit = positive(args, "limit", DEFAULT_LIMIT)
    max_seconds = seconds(args, "max_seconds", DEFAULT_MAX_SECONDS, MAX_SECONDS_CAP)
    deadline = started + max_seconds
    values = open_values(args)
    if pattern is not None and not values.enabled:
        # A filter answers "does this match?" for every fragment at once, and the answer lists which fragments
        # matched: with text you cannot see, one call is one bit of every fragment, and a few hundred calls
        # rebuild a token. A filter is therefore only a way to narrow what is written to the sealed values file.
        fail("contains narrows the sealed values file: it needs write_values: true, in a job run with secret_output: true. "
             "Without them a filter would tell you, fragment by fragment, whether text you cannot see matches it. "
             "Nothing was scanned.", contains_refused=True)

    file_bytes = os.path.getsize(db)
    real = shown(os.path.realpath(db), False)
    source = shown(db, False)
    problems = Problems(LosslessPage(TOOL, [real, "problems"], PROBLEMS_INLINE))
    fragments = LosslessPage(TOOL, [real, "fragments", contains or "", minimum], limit, INLINE_BYTES)

    with open(db, "rb") as scan, open(db, "rb") as walk, open(db, "rb") as verify:
        head = scan.read(100)
        if len(head) < 100 or head[:16] != MAGIC:
            # What the file starts with is not printed: it may be content, or a salt. Its size and the entropy of
            # its first 4 KiB say whether it looks encrypted or compressed.
            sample = scan.read(4096 - len(head)) if len(head) < 4096 else b""
            values.close()
            fail("this is not a SQLite database: its first 16 bytes are not the SQLite header string",
                 db=shown(db), bytes=file_bytes, entropy_bits_per_byte_of_first_4096=(None if entropy(head + sample) is None else round(entropy(head + sample), 2)),
                 note="High entropy is one explanation among others (encryption, compression); it is not an identification.")
        h = header_of(head)
        page_size, usable = h["page_size"], h["usable_size"]
        if page_size < 512 or page_size & (page_size - 1):
            values.close()
            fail("unsupported: the header's page size is not a power of two from 512 to 65536", page_size=page_size, db=shown(db))
        if usable < 480:
            values.close()
            fail("unsupported: the header leaves a usable page size under 480 bytes", usable_size=usable, db=shown(db))
        if h["read_version"] > 2:
            values.close()
            fail("unsupported: the header's read format version is %d, and only 1 (rollback journal) and 2 (WAL) are handled" % h["read_version"],
                 db=shown(db))
        in_file = -(-file_bytes // page_size)
        if h["declared_size_valid"] and h["pages_declared"] > in_file:
            problems.add("file shorter than its header says", "the header declares %d pages and the file holds %d" % (h["pages_declared"], in_file), True)
        if h["declared_size_valid"] and h["pages_declared"] < in_file:
            problems.add("pages beyond the declared size", "%d pages after the header's declared size are read as whole stale pages" % (in_file - h["pages_declared"]), True)
        if file_bytes % page_size:
            problems.add("partial last page", "the file ends %d bytes into page %d" % (file_bytes % page_size, in_file), False, page=in_file)
        if h["payload_fractions"] != [64, 32, 32]:
            problems.add("unusual header field", "the payload fractions are %s, not 64, 32, 32" % h["payload_fractions"], True)
        if h["text_encoding"] not in TEXT_ENCODINGS and h["text_encoding"] != 0:    # 0: no schema has been written yet
            problems.add("unusual header field", "the text encoding field is %d (1 UTF-8, 2 UTF-16LE, 3 UTF-16BE)" % h["text_encoding"], True)

        # A companion that is not read is a part of the database that is not examined.
        companions = {}
        for suffix in ("-wal", "-shm", "-journal"):
            try:
                size = os.lstat(db + suffix).st_size
            except OSError:
                continue
            companions[suffix] = {"bytes": size, "examined": False}
            if suffix != "-shm" and size > 0:
                problems.add("companion not examined", "%s%s is %d bytes and is not read by this tool: what it holds (committed changes, earlier page images) is absent from this answer" % (os.path.basename(db), suffix, size), False)

        patterns = compile_runs(minimum)
        # One UTF-16 byte order, the database's own: a Greek text read in the other order at the other parity is
        # Greek again, so scanning both would report the one text twice, each time cut.
        encodings = ["utf-16be"] if h["text_encoding"] == 3 else ["utf-16le"]
        wide_minimum = max(minimum, WIDE_MINIMUM)

        # The freelist: each trunk page names the leaves that follow it. A trunk seen twice, a page
        # outside the file and a count the header does not agree with are said, not walked past.
        free = {}
        trunks = 0
        trunk, seen = h["freelist_head"], set()
        max_leaves = usable // 4 - 2
        while trunk:
            if trunk in seen:
                problems.add("freelist cycle", "trunk page %d is reached twice: the rest of the chain is not followed" % trunk, False, page=trunk)
                break
            if trunk < 2 or trunk > in_file:
                problems.add("freelist page outside the file", "the chain names page %d, and the file has %d pages" % (trunk, in_file), False, page=trunk)
                break
            seen.add(trunk)
            walk.seek((trunk - 1) * page_size)
            page = walk.read(page_size)
            if len(page) < page_size:
                problems.add("freelist trunk page truncated", "page %d is cut short by the end of the file" % trunk, False, page=trunk)
                break
            following, count = struct.unpack_from(">II", page, 0)
            if count > max_leaves:
                problems.add("freelist trunk count too large", "page %d lists %d leaves and holds at most %d: the first %d are taken" % (trunk, count, max_leaves, max_leaves), True, page=trunk)
                count = max_leaves
            trunks += 1
            free[trunk] = (8 + count * 4, "freelist trunk page")
            for i in range(count):
                leaf = struct.unpack_from(">I", page, 8 + i * 4)[0]
                if leaf < 2 or leaf > in_file:
                    problems.add("freelist page outside the file", "trunk %d lists leaf %d, and the file has %d pages" % (trunk, leaf, in_file), False, page=trunk)
                elif leaf in free:
                    problems.add("freelist page listed twice", "page %d is listed more than once on the freelist" % leaf, True, page=leaf)
                else:
                    free[leaf] = (0, "freelist leaf page")
            trunk = following
        if len(free) != h["freelist_declared"]:
            problems.add("freelist count differs from the header", "the header declares %d freelist pages and the chain holds %d" % (h["freelist_declared"], len(free)), True)

        # Pages that are neither b-tree pages nor free: the lock-byte page of a file past 1 GiB and, in an
        # auto-vacuum database, the pointer-map pages (SQLite puts a pointer-map page one page later when it
        # would fall on the lock-byte page).
        lock_page = LOCK_BYTE_OFFSET // page_size + 1
        pointer_maps = set()
        if h["largest_root"]:
            span = usable // 5 + 1
            page_no = 2
            while page_no <= in_file + 1:
                pointer_maps.add(page_no + 1 if page_no == lock_page else page_no)
                page_no += span

        counts = {"pages_in_file": in_file, "pages_examined": 0, "pages_not_btree": 0, "pages_corrupt": 0,
                  "pages_partial": 0, "lock_byte_pages_skipped": 0, "pointer_map_pages_skipped": 0,
                  "freelist_trunk_pages": 0, "freelist_leaf_pages": 0, "freeblocks": 0, "unallocated_gaps": 0,
                  "regions_scanned": 0, "bytes_scanned": 0, "fragments_found": 0,
                  "fragments_unverified": 0, "candidates_dropped_as_overlapping": 0, "pages_not_reached": 0,
                  "contains_timeouts": 0}
        stopped_at = None
        serial = 0

        def region_fragments(number, base_in_page, region, where, extra):
            nonlocal serial
            counts["regions_scanned"] += 1
            counts["bytes_scanned"] += len(region)
            found, dropped = runs_in(region, patterns, encodings, wide_minimum)
            counts["candidates_dropped_as_overlapping"] += dropped
            for start, end, encoding in found:
                if time.monotonic() > deadline:
                    raise OutOfTime()
                raw = region[start:end]
                text = decode(raw, encoding)
                characters = len(text)
                counts["fragments_found"] += 1
                # contains only narrows what is written to the sealed values file. The answer lists every fragment whatever
                # the expression says: a list of the fragments that matched would answer, for each fragment, whether text
                # you cannot see matches, and a few hundred calls rebuild a token.
                hit = True
                if pattern is not None:
                    try:
                        hit = timed_search(pattern, text, max(0.01, min(REGEX_SECONDS, deadline - time.monotonic()))) is not None
                    except Timeout:
                        hit = False
                        counts["contains_timeouts"] += 1
                        problems.add("contains took too long", "the expression ran past its time on a fragment: that fragment is not written to the values file", False)
                absolute = (number - 1) * page_size + base_in_page + start
                verify.seek(absolute)
                again = verify.read(len(raw))
                verified = again == raw
                serial += 1
                finding = "F%06d" % serial
                if not verified:
                    counts["fragments_unverified"] += 1
                    problems.add("fragment not found at its offset", "the bytes at offset %d are not the bytes found in the page: not trusted" % absolute, False, page=number, finding_id=finding)
                row = {"finding_id": finding, "source": source, "page": number, "where": where, "encoding": encoding,
                       "offset": absolute, "offset_verified": verified, "bytes": len(raw),
                       "characters": characters, "parser": PARSER, **extra}
                fragments.add(row)
                if hit:
                    values.add(finding, {"file": os.path.realpath(db), "page": number, "where": where, "encoding": encoding,
                                         "offset": absolute, "bytes": len(raw), "characters": characters}, text)

        scan.seek(0)
        number = 0
        try:
            for number in range(1, in_file + 1):
                if time.monotonic() > deadline:
                    raise OutOfTime()
                page = scan.read(page_size)
                if number == lock_page and file_bytes > LOCK_BYTE_OFFSET:
                    counts["lock_byte_pages_skipped"] += 1
                    continue
                if number in pointer_maps:
                    counts["pointer_map_pages_skipped"] += 1
                    continue
                if len(page) < page_size:
                    counts["pages_partial"] += 1
                    continue
                counts["pages_examined"] += 1
                beyond = h["declared_size_valid"] and number > h["pages_declared"]
                if beyond:
                    region_fragments(number, 0, page[:usable], "page beyond the header's declared size", {})
                    continue
                if number in free:
                    data_start, description = free[number]
                    counts["freelist_trunk_pages" if description.endswith("trunk page") else "freelist_leaf_pages"] += 1
                    region_fragments(number, data_start, page[data_start:usable], description, {})
                    continue
                offset = 100 if number == 1 else 0
                kind = page[offset]
                if kind not in (2, 5, 10, 13):
                    counts["pages_not_btree"] += 1
                    continue
                first_free = struct.unpack_from(">H", page, offset + 1)[0]
                cells = struct.unpack_from(">H", page, offset + 3)[0]
                content = struct.unpack_from(">H", page, offset + 5)[0] or 65536
                header_size = 12 if kind in (2, 5) else 8
                gap_from = offset + header_size + cells * 2
                if gap_from > usable or content > usable or content < gap_from:
                    counts["pages_corrupt"] += 1
                    problems.add("b-tree page header inconsistent", "page %d: %d cells end at %d, the cell content area starts at %d, the usable size is %d: not examined" % (number, cells, gap_from, content, usable), False, page=number)
                    continue
                if content > gap_from:
                    counts["unallocated_gaps"] += 1
                    region_fragments(number, gap_from, page[gap_from:content], "unallocated space in page", {})
                block, guard = first_free, 0
                while block:
                    guard += 1
                    if block < content or block + 4 > usable or guard > usable // 4:
                        problems.add("freeblock chain corrupt", "page %d: the chain reaches offset %d (cell content starts at %d, usable size %d): the rest of the chain is not followed" % (number, block, content, usable), False, page=number)
                        break
                    following, size = struct.unpack_from(">HH", page, block)
                    if size < 4 or block + size > usable:
                        problems.add("freeblock chain corrupt", "page %d: the freeblock at %d declares %d bytes (usable size %d): not read, the rest of the chain is not followed" % (number, block, size, usable), False, page=number)
                        break
                    if following and following <= block:
                        problems.add("freeblock chain corrupt", "page %d: the freeblock at %d points back to %d: a loop or an unordered chain, not followed past it" % (number, block, following), True, page=number)
                        following = 0
                    counts["freeblocks"] += 1
                    # The freeblock's own header is its first four bytes (next offset, size): the
                    # deleted cell's bytes start after it, and so does the offset reported.
                    region_fragments(number, block + 4, page[block + 4:block + size], "freeblock in page", {"block_offset": block})
                    block = following
        except OutOfTime:
            stopped_at = number
            counts["pages_not_reached"] = in_file - number + 1
            problems.add("time limit", "max_seconds (%s) passed in page %d: that page may be partly read, and pages %d to %d are not examined" % (max_seconds, number, number, in_file), False, page=number)
        if counts["pages_not_btree"] and any(k.startswith("freelist") for k in problems.kinds):
            problems.add("pages not read after a freelist problem",
                         "%d pages are neither b-tree pages nor on the freelist as walked. Overflow pages hold live content "
                         "and are not read; after the freelist problem above some of them may be free pages whose text is "
                         "not examined" % counts["pages_not_btree"], False)

    values.close()
    paging = {"fragments": fragments.finish(), "problems": problems.page.finish()}
    corrupt = any(kind in CORRUPT_KINDS for kind in problems.kinds)
    complete = problems.unexamined == 0 and stopped_at is None
    status = "corrupt" if corrupt else ("complete" if complete else "partial")
    send({
        "db": shown(db),
        "parser": PARSER,
        "status": status,
        "database": {
            "page_size": page_size, "usable_size": usable, "reserved_bytes": h["reserved_bytes"],
            "bytes": file_bytes, "pages_in_file": in_file, "pages_declared": h["pages_declared"],
            "declared_size_valid": h["declared_size_valid"],
            "text_encoding": TEXT_ENCODINGS.get(h["text_encoding"], "unknown (%d)" % h["text_encoding"]),
            "journal_mode_on_disk": "WAL" if h["write_version"] == 2 else "rollback journal",
            "auto_vacuum": bool(h["largest_root"]),
            "user_version": h["user_version"], "application_id": "0x%08x" % h["application_id"],
            "sqlite_version_number": h["sqlite_version_number"],
        },
        "freelist": {"declared": h["freelist_declared"], "walked": len(free), "trunk_pages": trunks},
        "scanned": counts,
        "encodings_scanned": ["utf-8"] + encodings,
        "stopped_before_page": stopped_at,
        "problems": problems.page.page,
        "problem_kinds": problems.kinds,
        "fragments": fragments.page,
        "fragment_count": counts["fragments_found"],
        "filter": scrub(contains) if contains else None,
        "filter_narrows": "the values file only (the fragments listed here are all of them, whatever the expression matched)" if contains else None,
        "pages": paging,
        "companions": companions,
        "secret_values": {**values.summary(), "written": None, "contains_secret_values": None,
                          "count_withheld": "contains narrowed the values file: how many fragments matched is not shown"} if pattern is not None else values.summary(),
        "paths_withheld": PATHS_WITHHELD[0],
        **({"paths_note": "A path component shaped like a recovery password is withheld from every path in this answer and in "
                          "the files it names; the real path is in the values file when write_values was asked for."}
           if PATHS_WITHHELD[0] else {}),
        "truncated": any(p["truncated"] for p in paging.values()),
        "note": "A fragment is TEXT found in space the database's main file no longer uses: no column, no table, no "
                "time, no row boundary, and the page may have belonged to something else entirely. The answer "
                "carries where each fragment is (page, kind of region, byte offset, length, encoding) and never its "
                "text: the text is in the values file when write_values was asked for in a job run with "
                "secret_output. Offsets were read back from the file and compared (offset_verified). Only the main "
                "file is read: a -wal or -journal listed under companions is NOT examined (its frames and page "
                "images are not read), so what it holds, including the newest committed changes, is absent from "
                "this answer, and a non-empty one makes the status partial. Encodings are UTF-8 and UTF-16LE "
                "(UTF-16BE instead of it where the header declares UTF-16BE); a negative covers only those encodings, only the regions "
                "counted under scanned, and says nothing about a vacuumed database or one that used secure_delete. "
                "contains is accepted only with write_values: it narrows the sealed values file, and the list in this "
                "answer is every fragment whatever it matched (how many matched is not shown), since a list of the "
                "matches would answer, fragment by fragment, whether text you cannot see matches. Status is complete (every page examined, nothing inconsistent, no companion left unread), "
                "partial (a limit, a companion not read, or pages or regions not examined) or corrupt (the file's "
                "structure disagreed with itself where problems says; the fragments found are still reported, and "
                "a corrupt chain means text beyond it was not reached). A fragment is a candidate to corroborate, "
                "never a message.",
    })


if __name__ == "__main__":
    run_main(main)
