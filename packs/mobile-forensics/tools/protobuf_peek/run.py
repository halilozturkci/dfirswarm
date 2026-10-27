#!/usr/bin/env python3
"""Read a protobuf message that arrived without its schema: its wire structure, and nothing more.

More and more of Android and iOS stores its records as protobuf rather than as SQLite: usage
statistics, some Biome payloads, app caches. Without the .proto file there are no field names, but
the wire format carries each field's number, its wire type and its value, which is enough to see the
shape of a blob and to decide whether it matters.

The wire format, which is all this reads (protobuf encoding, as documented by the protobuf project):

    key       a varint: field number = key >> 3 (1 to 536870911), wire type = key & 7
    type 0    varint            an integer, a boolean, an enum, or a zigzag-encoded signed integer
    type 1    64-bit            a fixed64, an sfixed64 or a double
    type 2    length-delimited  a string, bytes, a nested message, or a packed repeated field
    type 5    32-bit            a fixed32, an sfixed32 or a float
    type 3, 4 start and end of a group: deprecated, NOT supported here (see below)

A varint is at most ten bytes, and the tenth may hold only the top bit of a 64-bit value; a longer one,
a field number of 0 or above 536870911, a wire type of 6 or 7 and a field that runs past its message
are structural errors. A message that holds a group is not parsed past the group and is never reported as valid
(its window is `not_accepted`, like every window that is not a message the rules show).

WHEN ROWS ARE PRINTED. What the field numbers, wire types, lengths and varints of a window show is
derived from its bytes: aimed at the payload of a string or a token, the tool would hand the
characters back as numbers, one call or a sliding window at a time. So rows are printed only for a
window that is a message: it parses whole, is at least eight bytes with at least two fields, is not entirely printable
text, writes every varint in its shortest form, orders its field numbers ascending and keeps them at 300 or below (random
bytes pass about once in 3,400; real Biome messages 17,871 times in 17,872). A window the caller aimed (an offset past the
start of the message, or a length) must also be at least sixteen bytes with at least four fields: the first answer names where
each withheld field's payload is, and a window slid across a token would otherwise print the token's characters as keys, lengths
and varints (measured with the plain rule on a token inside a message: between 13 and 99 percent of 12- to 64-character tokens
had a window that was shown, and 3 to 20 percent of a token's characters were derivable from what was printed; with this rule, for a
token that is the whole of one string field, 0 to 1.2 percent of tokens have such a window and at most 0.2 percent of a token's
characters are derivable, never a whole token). The rule is tuned to that layout, and it is weaker outside it: a token split
across two string fields had a shown window for 4.8 percent of 32-character hexadecimal tokens (0.8 percent of their characters
derivable), a 64-character hexadecimal token written as repeated six-byte pieces for 12.5 percent (1.1 percent of characters), a
32-byte token as repeated six-byte pieces for 8.1 percent (0.5 percent), and a 64-character hexadecimal token inside a nested
message for 3.9 percent (0.4 percent); never a whole token in any of them. These rates hold whatever `max_fields` the caller sets:
a window the field budget stopped is shown only when nobody aimed it (a caller who sets max_fields 4 would otherwise have an aimed window
judged on its first four fields, whatever follows, and had a shown window for 19 to 21 percent of 64-character hexadecimal tokens, 6
percent of 32-character ones and 1.2 percent of 24-character base62 ones, with up to 2 percent of the token's bytes derivable). A window that is not
accepted, which includes most windows aimed at the payload of a field this tool withheld, gets a status and counts, no row, no
field number, no varint and no number in a reason, and NO COUNT: not the number of fields, not the number of top-level fields, not
how many were varints or nested, not how deep, and not whether the parse met a group (the parse stops at the first error, so
those numbers come from the bytes of a token as much as the rows would: a window slid over a token gave about two bits per
character through them). Every window that is not accepted gets the same status, `not_accepted`, and the same words. Its bytes
are in the job's values file on request, as one row of the same size as the window (hexadecimal, with the parser's finding in
a fixed width), not as the rows the parse found: a file whose size follows the number of fields parsed would answer the same
question. What the values file's size still follows is how JSON writes the TEXT of a string field: a quote or a backslash adds a
byte, a control character or a non-ASCII one adds more (bytes, nested payloads, numbers and windows are written in a width the answer
shows already). A caller who isolates a field with `offset` and `length` reads about log2(count+1) bits of that field's quote,
backslash and control-character count from the size of one call, and nothing from a token of letters and digits. The text is written
readable on purpose, so this is stated and not removed. Nor is the time of the parse of a window that is not shown: it stops at the first error,
so how long the call took says roughly how many fields were read before it (microseconds a field, visible to whoever sees the job's duration). The same rule decides
whether a length-delimited field is read as a nested message; printable text is text, never a nested message (a tag byte is a
printable character).

THE SHAPE IS NOT THE MEANING. `read_as` is a guess between a nested message, text and bytes. A varint
is returned raw, with its zigzag reading and, where it has the top bit set, its two's-complement
reading; which of them is meant is the schema's to say, and so is every field name, unit and enum. A
clean parse says the bytes are consistent with protobuf, not that they are one.

Offsets are absolute: the byte position in the file (the `offset` given, plus the position in the
window read), for a nested field as much as a top-level one, with the full field-number path
(`3.1.2`). Only a bounded window is read (`length`, 8 MiB by default, never more than 64 MiB; memory
follows the window, not its depth), and what lies past it is counted and next_offset is named.

THE SECRET-SAFE OUTPUT PATTERN. A protobuf blob can hold message text, a token or any other string.
In a printed window a top-level varint is printed (a timestamp, a counter and an enum are what it is
read for). Nothing else that holds a value is: not the text of a string field, not the bytes of a
bytes field or the payload of a nested message, not a number under a length-delimited field and not
a fixed-width value, which is raw bytes. The answer carries each one's offset, length and reading, and
the value goes only to the values file, on `write_values: true` in a job run with `secret_output:
true`. `hex` (a message passed in the call) is recorded in the trace: use it only for a few bytes that
are not sensitive, and a file for anything else.

WHAT A REQUESTING AGENT CAN SEE. The answer, and the job's file list with each file's size and digest, are what a requester is shown
without asking. The values file itself is under store/ of the sandbox, which an agent's VM mounts read-only: an agent that opens it reads
every row, the values (and `match`) included. The measures above protect what is shown without anyone opening the file (the answer, its
status and counts, the file's size and digest). They do not stop an agent that deliberately opens the sealed file, and this tool does not
decide whether it may: that is the sandbox's mounts.
"""
import binascii
import codecs
import errno
import hashlib
import json
import math
import os
import re
import select
import signal
import stat
import struct
import sys
import tempfile
import time
import unicodedata
from pathlib import Path

PARSER = "protobuf_peek/2"
TOOL = "protobuf_peek"
VALUES_NAME = "protobuf-values.jsonl"
VALUES_FORMAT = ("JSON Lines, mode 0600: finding_id, source (the real file), field_path, offset, payload_offset, "
                 "kind (text, bytes, nested_payload, number or window), bytes, run (random, the same in every row of this run), value (the "
                 "text, the bytes as hexadecimal, or the number's readings padded to a fixed width). A window that was not accepted is "
                 "one row of kind window: value is the whole window as hexadecimal, and parse is the parser's finding (state, reason, "
                 "offset) in a fixed width")


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
#      (JOB_ID and OUT are set) that the harness ran as secret output (SECRET_OUTPUT=1, which the
#      manifest's `secret_output` declaration makes the job service set), and only to a file under
#      $OUT: JSON Lines, mode 0600, created exclusively before anything is read. Outside such a job
#      the request is refused as JSON and nothing is written.
#   3. A secret is never on a command line: these tools take a path and flags only.
#   4. A printed path component shaped like a recovery password is withheld on every output
#      channel (the answer, the files it names, an error message); the values file keeps the
#      real path.
#   5. The harness shows the requester a sealed file's size and digest, so neither may answer a
#      question about text nobody can see: a filter marks rows and never drops them, a window or an
#      expression that is not accepted writes a file of the same size as one that is, and every row
#      carries a random per-run `run`, so that no two runs share a digest.
#   6. One document is written, whole: from the moment the answer is being written a stop signal is
#      ignored, so a reader that is slow never gets a truncated answer followed by a failure. A reader that
#      takes nothing for WRITE_STALL_SECONDS is given up on: the tool exits (141) instead of waiting for ever.

WITHHELD = "<recovery-password-shaped name withheld>"
WITHHELD_LONG = "<name too long to judge withheld>"
PATHS_WITHHELD = [0]
# A BitLocker recovery password is eight groups of six digits: 48 digits. People save a key under its own name, and not
# only in the dashed form: with spaces, underscores or dots between the groups, with no separator at all, with another
# dash, comma, colon, bracket or quote mark, in full-width or Arabic-Indic digits, with a zero-width character or an accent
# inside, and a name can carry part of it or be split across two path components. A text is shaped like one when it holds
# RECOVERY_DIGITS (seven groups of six) or more decimal digits in a run that allows at most three characters that are neither
# a letter nor a digit between two digits (a run of white space counts as one, and `/` is such a character), after NFKC
# folding (which turns full-width digits, superscripts and circled digits into ASCII ones). Fewer digits are a timestamp, a
# phone number or an id.
# The judgment is linear in the text: the maximal runs of digits and separators are found in one pass, and only a run long
# enough to hold RECOVERY_DIGITS digits is looked at again, at its start (a pattern tried from every digit costs 41 steps per
# character on "41 digits and a letter", repeated). A path is judged only up to JUDGE_CHARS characters: nothing a file system
# holds is longer, and a longer text is withheld whole instead of being read, so that the cost of one hostile cell stays small.
RECOVERY_DIGITS = 42
JUDGE_CHARS = 8192
SEPARATOR = r"[\W_]"
DIGIT_RUN = re.compile(r"\d(?:%s{0,3}\d)*" % SEPARATOR)
KEY_START = re.compile(r"\d(?:%s{0,3}\d){%d}" % (SEPARATOR, RECOVERY_DIGITS - 1))
SPACES = re.compile(r"\s+")


def folded(text):
    """NFKC, with every run of white space as one space."""
    return SPACES.sub(" ", unicodedata.normalize("NFKC", text))


def key_spans(text):
    """(start, end) of every run of `text` (already folded) that holds RECOVERY_DIGITS or more digits."""
    return [run.span() for run in DIGIT_RUN.finditer(text)
            if run.end() - run.start() >= RECOVERY_DIGITS and KEY_START.match(text, run.start())]


def key_shaped(text):
    return bool(key_spans(folded(text)))


def shown(path, count=True):
    """A path as it may be printed: a component that holds digits of a text shaped like a recovery password (a key split
    across components included) is withheld, and a path too long to judge is withheld whole."""
    if not isinstance(path, str):
        return path
    if len(path) > JUDGE_CHARS:
        if count:
            PATHS_WITHHELD[0] += 1
        return WITHHELD_LONG
    parts = path.split("/")
    texts = [folded(part) for part in parts]
    spans = key_spans("/".join(texts))
    if not spans:
        return path
    at, hidden = 0, []
    for i, text in enumerate(texts):
        if any(start < at + len(text) and end > at for start, end in spans):
            hidden.append(i)
        at += len(text) + 1
    for i in hidden:
        parts[i] = WITHHELD
        if count:
            PATHS_WITHHELD[0] += 1
    return "/".join(parts)


def scrub(text):
    """Text that may quote a path, with anything shaped like a recovery password withheld."""
    text = DIGIT_RUN.sub(lambda run: WITHHELD if run.end() - run.start() >= RECOVERY_DIGITS and KEY_START.match(run.string, run.start())
                         else run.group(), text)
    if key_shaped(text):      # digits only NFKC folds (superscripts, circled digits): the text is not printed at all
        return WITHHELD
    return text


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


# Things the run made that a failure or a stop must not leave behind (a working copy of an evidence file). Each is a
# callable that removes what the tool itself created; it is run once, by fail() and by a stop signal.
CLEANUP = []


def run_cleanup():
    while CLEANUP:
        step = CLEANUP.pop()
        try:
            step()
        except Exception:
            pass


def wrap_up(answer):
    """What an answer that ends the run early carries: the pages already written are closed and named, the values
    file is closed and counted, and what the tool made as scratch is removed."""
    kept = []
    for page in OPEN_PAGES:
        if page._out is not None:
            try:
                kept.append(page.finish().get("all_results"))
            except Exception:
                pass
    if kept:
        answer["rows_read_before_the_failure_kept_in"] = kept
    for values in OPEN_VALUES:
        values.close()
        if values.written:
            answer["values_written_before_the_failure"] = {"file": values.shown, "rows": values.written}
    run_cleanup()
    return answer


WRITE_STALL_SECONDS = 30


def write_stalled(signum, frame):
    sys.stderr.write("the reader took nothing for %d seconds: the answer is not delivered\n" % WRITE_STALL_SECONDS)
    raise SystemExit(141)


def emit(text):
    """Write one document to standard output, whole. From here a stop signal is ignored: the answer is written in one piece
    (a reader that is slow, or has not started, sees all of it) and never as a truncated document followed by a failure.
    A reader that takes nothing for WRITE_STALL_SECONDS is given up on (exit 141): without that, a pipe nobody reads could
    be ended only by SIGKILL."""
    for number in STOP_SIGNALS:
        signal.signal(number, signal.SIG_IGN)
    data = memoryview((text + "\n").encode("utf-8"))
    timed = hasattr(signal, "setitimer")
    if timed:
        try:
            signal.signal(signal.SIGALRM, write_stalled)
        except ValueError:      # not the main thread: no deadline
            timed = False
    try:
        sys.stdout.flush()
        descriptor = sys.stdout.fileno()
        while len(data):
            if timed:
                signal.setitimer(signal.ITIMER_REAL, WRITE_STALL_SECONDS)       # progress restarts the wait
            try:
                data = data[os.write(descriptor, data):]
            except BlockingIOError:      # a pipe set non-blocking by its owner and full: wait until it can take more
                select.select([], [descriptor], [], 1.0)
    except OSError:       # the reader went away: there is nobody to answer
        raise SystemExit(1)
    finally:
        if timed:
            signal.setitimer(signal.ITIMER_REAL, 0)


def fail(message, **extra):
    answer = {"error": scrub(str(message)), **{k: (scrub(v) if isinstance(v, str) else v) for k, v in extra.items()}}
    emit(dumps(wrap_up(answer)))
    raise SystemExit(1)


class Interrupted(BaseException):
    """A stop signal (SIGTERM, SIGINT or SIGHUP) arrived. A BaseException, so that no `except Exception` of a tool
    swallows it; run_main answers for it once, at the top."""

    def __init__(self, signum):
        BaseException.__init__(self, signum)
        self.signum = signum


STOP_SIGNALS = [getattr(signal, name) for name in ("SIGTERM", "SIGINT", "SIGHUP") if hasattr(signal, name)]


def stop_handler(signum, frame):
    # The answer to the first signal is written once: a second signal while it is written changes nothing.
    for number in STOP_SIGNALS:
        signal.signal(number, signal.SIG_IGN)
    raise Interrupted(signum)


def stopped(signum):
    """One JSON answer for a run a signal ended, then exit 128 + the signal. The pages and the values file are closed
    and named, the scratch the tool made is removed, and nothing is said about what the tool had read."""
    name = signal.Signals(signum).name
    answer = wrap_up({"error": "the tool was stopped by %s before it finished: this is not an answer to the question" % name,
                      "status": "failed", "status_basis": "stopped by %s before the answer was complete" % name,
                      "interrupted": name})
    emit(dumps(answer))
    raise SystemExit(128 + signum)


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
        self.run = os.urandom(8).hex()      # in every row: the file's digest is different in every run, whatever it holds
        if not enabled:
            return
        if not (self.job and self.out):
            raise SecretValuesRefused(
                "write_values is refused outside a job: a value written here would be an ordinary "
                "file, not a sealed secret output. Run this as job_run tool=%s with "
                "secret_output: true, and ask again there. Nothing was written." % TOOL
            )
        if os.environ.get("SECRET_OUTPUT") != "1":
            raise SecretValuesRefused(
                "write_values is refused in a job that is not run as secret output (SECRET_OUTPUT is not 1): the values file would "
                "be sealed as ordinary output. The harness sets SECRET_OUTPUT=1 for a secret job's process and it is not set here. "
                "Run this as job_run tool=%s with secret_output: true, and ask again there. Nothing was written." % TOOL
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
        self._fh.write(dumps({"finding_id": finding_id, **locator, "run": self.run, "value": value}))
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
    emit(dumps(result, indent=2))


def run_main(main):
    for number in STOP_SIGNALS:
        signal.signal(number, stop_handler)
    try:
        try:
            main()
        except SystemExit:
            raise
        except Exception as exc:  # never an empty or clean answer for a failure, and never a traceback
            fail("unexpected failure: " + (describe(exc) if isinstance(exc, OSError) else "%s: %s" % (type(exc).__name__, exc)))
    except Interrupted as stop:
        stopped(stop.signum)
# --- shared with the pack's other tools: end -----------------------------------------------

WIRE = {0: "varint", 1: "64-bit", 2: "length-delimited", 3: "start group", 4: "end group", 5: "32-bit"}
MAX_FIELD_NUMBER = (1 << 29) - 1
DEFAULT_WINDOW = 8 << 20
HARD_WINDOW = 64 << 20
HEX_LIMIT = 65536
DEFAULT_DEPTH, HARD_DEPTH = 6, 32
DEFAULT_FIELDS, HARD_FIELDS = 100000, 500000
DEFAULT_LIMIT = 200
INLINE_BYTES = 1 << 20
DEFAULT_SECONDS = 60
MAX_SECONDS_CAP = 90          # manifest.json timeout_seconds (120) less the time to write the answer
# A message is accepted (its rows are shown, or a length-delimited field is read as one) only when it parses
# whole, has at least two fields, writes every varint in its shortest form, orders its field numbers
# ascending and keeps them up to this. Real messages do. Random bytes rarely do (29 of 100,000 random 16-byte values, 4 of
# 100,000 random 32-byte values), and printable text never reaches the rule (it is text, see window_accepted_by). What an
# accepted reading shows is derived from those bytes.
NESTED_FIELD_MAX = 300
# A window is judged by a stricter rule when the caller aimed it (an offset past the start, or a length). The first
# answer names where every withheld field's payload is, so a caller can aim a window at a token and slide it, and
# the rows of an accepted sub-window are the token's own characters read as keys, lengths and varints. A window is
# shown only if
#   - it is not entirely printable text: a message is not, and every window inside a string or a token is,
#   - it is at least MIN_AIMED_BYTES long and holds at least MIN_AIMED_FIELDS fields when it was aimed,
#   - and it meets the rule above.
# A window that was not aimed (offset 0, no length) is held to the rule above, to MIN_WINDOW_BYTES and to the
# printable-text test.
REASON_WIDTH = 160            # the parser's reasons are all shorter; the values file writes one in this width
NUMBER_WIDTH = 480            # a withheld number's readings are written in this width (the longest are about 250 characters)
MIN_WINDOW_BYTES = 8
MIN_AIMED_BYTES = 16
MIN_AIMED_FIELDS = 4
CONTROL_FREE = bytes([0x09, 0x0A, 0x0D]) + bytes(range(0x20, 0x7F)) + bytes(range(0x80, 0x100))
NUMBER_KEYS = ("value", "as_bool", "zigzag_reading", "twos_complement_reading", "hex", "float_reading", "double_reading")
TEXT_FILTER = str.maketrans("", "", "\n\r\t")


class Context:
    def __init__(self, blob, base, max_depth, max_fields, deadline):
        self.blob = blob
        self.view = memoryview(blob)
        self.base = base
        self.max_depth = max_depth
        self.max_fields = max_fields
        self.deadline = deadline
        self.fields = 0
        self.stopped = None
        self.stop_at = None
        self.depth_limited = 0


def read_varint(blob, at, end):
    """(value, next, problem, minimal): a varint of at most ten bytes whose tenth byte is 0 or 1. The reasons
    carry no number: what a number would show is derived from the bytes."""
    value, shift, start = 0, 0, at
    while True:
        if at >= end:
            return None, at, "a varint runs past the end of its message", True
        byte = blob[at]
        at += 1
        if shift == 63 and byte > 1:
            return None, at, "a varint is longer than a 64-bit value", True
        value |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return value, at, None, not (at - start > 1 and byte == 0)
        shift += 7
        if shift > 63:
            return None, at, "a varint is longer than ten bytes", True


def text_characters(view):
    """The number of characters when the bytes are printable UTF-8 text (tab and line ends allowed), else None.
    Every character, not most of them: a real string has no control bytes, a nested message nearly always does."""
    if not len(view):
        return None
    try:
        text, _ = codecs.utf_8_decode(view, "strict", True)
    except UnicodeDecodeError:
        return None
    return len(text) if text.translate(TEXT_FILTER).isprintable() else None


def parse(ctx, start, end, depth, path):
    """(rows, state, problem, shape) for the message in blob[start:end].

    state is ok, invalid (a structural error, in `problem`), unsupported (a group) or stopped (the budget or the
    clock). shape holds what the acceptance rule needs. Rows carry spans of the window for text, bytes and
    nested payloads, never copies of them.
    """
    rows, at = [], start
    shape = {"fields": 0, "minimal": True, "ordered": True, "small": True}
    last = 0
    while at < end:
        ctx.fields += 1
        if ctx.fields > ctx.max_fields:
            ctx.stopped, ctx.stop_at = "max_fields (%d) reached" % ctx.max_fields, ctx.base + at
            return rows, "stopped", {"offset": ctx.base + at, "reason": ctx.stopped}, shape
        if ctx.fields % 256 == 0 and time.monotonic() > ctx.deadline:
            ctx.stopped, ctx.stop_at = "max_seconds passed", ctx.base + at
            return rows, "stopped", {"offset": ctx.base + at, "reason": ctx.stopped}, shape
        field_start = at
        key, at, bad, minimal = read_varint(ctx.blob, at, end)
        if bad:
            return rows, "invalid", {"offset": ctx.base + field_start, "reason": bad}, shape
        shape["minimal"] = shape["minimal"] and minimal
        number, wire = key >> 3, key & 7
        if number == 0 or number > MAX_FIELD_NUMBER:
            return rows, "invalid", {"offset": ctx.base + field_start,
                                      "reason": "a field number of 0, or above 536870911"}, shape
        shape["fields"] += 1
        if number < last:
            shape["ordered"] = False
        last = number
        if number > NESTED_FIELD_MAX:
            shape["small"] = False
        field_path = path + [number]
        row = {"field_path": ".".join(str(n) for n in field_path), "field": number, "wire_type": WIRE.get(wire, str(wire)),
               "depth": depth, "offset": ctx.base + field_start}
        if wire in (3, 4):
            return rows, "unsupported", {"offset": ctx.base + field_start,
                                         "reason": "a group (wire type 3 or 4): groups are deprecated and not parsed, and nothing after "
                                                   "this point in this message is read"}, shape
        if wire not in (0, 1, 2, 5):
            return rows, "invalid", {"offset": ctx.base + field_start, "reason": "a wire type that is not defined (6 or 7)"}, shape
        if wire == 0:
            value, at, bad, minimal = read_varint(ctx.blob, at, end)
            if bad:
                return rows, "invalid", {"offset": ctx.base + field_start, "reason": bad}, shape
            shape["minimal"] = shape["minimal"] and minimal
            row["value"] = value
            if value in (0, 1):
                row["as_bool"] = bool(value)
            row["zigzag_reading"] = (value >> 1) ^ -(value & 1)
            if value >= 1 << 63:
                row["twos_complement_reading"] = value - (1 << 64)
        elif wire in (1, 5):
            size = 8 if wire == 1 else 4
            if at + size > end:
                return rows, "invalid", {"offset": ctx.base + field_start,
                                         "reason": "a fixed-width field runs past the end of its message"}, shape
            raw = ctx.blob[at:at + size]
            at += size
            row["value"] = int.from_bytes(raw, "little")
            row["hex"] = raw.hex()
            real = struct.unpack("<d" if wire == 1 else "<f", raw)[0]
            if math.isfinite(real):
                row["float_reading" if wire == 5 else "double_reading"] = real
        else:
            length, at, bad, minimal = read_varint(ctx.blob, at, end)
            if bad:
                return rows, "invalid", {"offset": ctx.base + field_start, "reason": bad}, shape
            shape["minimal"] = shape["minimal"] and minimal
            if at + length > end:
                return rows, "invalid", {"offset": ctx.base + field_start,
                                         "reason": "a length-delimited field runs past the end of its message"}, shape
            row["payload_offset"] = ctx.base + at
            row["payload_bytes"] = length
            payload = ctx.view[at:at + length]
            characters = text_characters(payload)
            # Printable text is text, never a nested message: a nested reading of a string would show its
            # characters as field numbers, wire types and lengths (a tag byte is a printable character).
            if length == 0:
                row["read_as"] = "empty"
            elif characters is not None:
                row["read_as"] = "text"
                row["characters"] = characters
                row["_span"] = ("text", at, at + length)
            else:
                nested, tried_whole = None, False
                if depth < ctx.max_depth:
                    inner, state, _, inner_shape = parse(ctx, at, at + length, depth + 1, field_path)
                    if ctx.stopped:
                        return rows, "stopped", {"offset": ctx.base + field_start, "reason": ctx.stopped}, shape
                    tried_whole = state == "ok" and bool(inner)
                    if accepted(state, inner_shape):
                        nested = inner
                else:
                    ctx.depth_limited += 1
                if nested:
                    row["read_as"] = "nested message"
                    row["children"] = len(nested)
                    row["_children"] = nested
                    row["_span"] = ("nested", at, at + length)
                else:
                    row["read_as"] = "bytes"
                    row["_span"] = ("bytes", at, at + length)
                    if tried_whole:
                        row["also_reads_as"] = ["a message that does not meet the acceptance rule"]
            at += length
        rows.append(row)
    return rows, "ok", None, shape


def window_rule_failed(blob, state, shape, aimed):
    """None when the rows of the whole window may be printed, else a short code for the first rule it fails: the acceptance
    rule, a length and a field count that depend on whether the caller aimed the window, and the test that it is not text.
    The code goes to the values file only."""
    if len(blob) < (MIN_AIMED_BYTES if aimed else MIN_WINDOW_BYTES):
        return "too_short"
    if aimed and shape["fields"] < MIN_AIMED_FIELDS:
        return "too_few_fields_aimed"
    # A control byte other than tab and the line ends means it is not text: the common case, decided without decoding.
    if not blob.translate(None, CONTROL_FREE) and text_characters(memoryview(blob)) is not None:
        return "printable_text"
    # A parse the budget or the clock stopped is judged on the fields it read. For a window the caller aimed that would let the caller
    # choose how many fields decide (max_fields 4: acceptance on the first four, whatever follows), and a window slid over a token has
    # a shown window for 19 to 21 percent of 64-character hexadecimal tokens instead of 1 percent: an aimed window is shown only when
    # the whole of it was parsed.
    if state != "ok" and not (state == "stopped" and not aimed):
        return "parse_" + state
    if shape["fields"] < 2:
        return "fewer_than_two_fields"
    if not shape["minimal"]:
        return "not_shortest_varint"
    if not shape["ordered"]:
        return "unordered_fields"
    if not shape["small"]:
        return "large_field_number"
    return None


def window_accepted_by(blob, state, shape, aimed):
    """Whether the rows of the whole window may be printed (see window_rule_failed)."""
    return window_rule_failed(blob, state, shape, aimed) is None


def accepted(state, shape):
    """The acceptance rule, for a nested reading and for the whole window alike. A parse the budget stopped
    is judged on what it read; one that hit an error or a group is not accepted."""
    return (state in ("ok", "stopped") and shape["fields"] >= 2 and shape["minimal"] and shape["ordered"] and shape["small"])


def main():
    started = time.monotonic()
    args = read_args()
    values = open_values(args)
    limit = positive(args, "limit", DEFAULT_LIMIT)
    max_depth = args.get("max_depth", DEFAULT_DEPTH)
    if not isinstance(max_depth, int) or isinstance(max_depth, bool) or not 0 <= max_depth <= HARD_DEPTH:
        fail("max_depth must be an integer from 0 to %d" % HARD_DEPTH, max_depth=max_depth)
    max_fields = positive(args, "max_fields", DEFAULT_FIELDS, HARD_FIELDS)
    max_seconds = seconds(args, "max_seconds", DEFAULT_SECONDS, MAX_SECONDS_CAP)
    offset = args.get("offset", 0)
    if not isinstance(offset, int) or isinstance(offset, bool) or offset < 0:
        fail("offset must be a non-negative integer")
    length = args.get("length")
    if length is not None:
        length = positive(args, "length", None, HARD_WINDOW)
    if args.get("hex") and args.get("path"):
        fail("give path or hex, not both: hex is a message in the call (recorded in the trace), path a file")

    window = {}
    if args.get("hex"):
        if not isinstance(args["hex"], str):
            fail("hex must be a string")
        try:
            data = binascii.unhexlify("".join(args["hex"].split()))
        except (binascii.Error, ValueError) as exc:
            fail("hex is not valid hexadecimal", reason=str(exc))
        if len(data) > HEX_LIMIT:
            fail("hex is limited to %d bytes: what is passed in a call is recorded in the trace; pass a file with path" % HEX_LIMIT,
                 bytes=len(data))
        source, source_real, file_bytes = "hex", "hex", None
        if offset > len(data):
            fail("offset is past the end of the message", offset=offset, bytes=len(data))
        blob = data[offset:]
        if length is not None:
            blob = blob[:length]
        window = {"offset": offset, "bytes": len(blob), "file_bytes": None, "bytes_after_window": len(data) - offset - len(blob)}
    else:
        path = args.get("path")
        if not isinstance(path, str) or not path:
            fail("path or hex is required: a file holding a protobuf message")
        try:
            # O_NONBLOCK so that a named pipe cannot hold the tool: a path that is not a regular file is refused.
            fd = os.open(path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0))
        except OSError as exc:
            fail("cannot read that file", path=shown(path, False), reason=describe(exc))
        with os.fdopen(fd, "rb") as fh:
            info = os.fstat(fh.fileno())
            if not stat.S_ISREG(info.st_mode):
                fail("that path is not a regular file", path=shown(path, False))
            file_bytes = info.st_size
            if offset > file_bytes:
                fail("offset is past the end of the file", offset=offset, bytes=file_bytes)
            want = min(length or DEFAULT_WINDOW, file_bytes - offset)
            fh.seek(offset)
            blob = fh.read(want)
        source, source_real = shown(path), os.path.realpath(path)
        window = {"offset": offset, "bytes": len(blob), "file_bytes": file_bytes, "bytes_after_window": file_bytes - offset - len(blob)}
        if len(blob) < want:
            window["short_read"] = "the file returned %d of %d bytes asked for" % (len(blob), want)
    if window["bytes_after_window"] > 0:
        window["next_offset"] = offset + len(blob)
        window["note"] = ("Only this window was read: the %d bytes after it are not decoded. next_offset is where the next window of "
                          "a message that parsed whole starts; a message that spans the boundary is reported as running past its end."
                          % window["bytes_after_window"])

    ctx = Context(blob, offset, max_depth, max_fields, started + max_seconds)
    rows, state, problem, shape = parse(ctx, 0, len(blob), 0, [])
    aimed = offset > 0 or length is not None
    window_accepted = window_accepted_by(blob, state, shape, aimed)

    # The counts of a window that is not accepted stay zero: the parse stops at the first error, so how many fields it read, how
    # many were varints or nested, and how deep it went come from the window's bytes, as the rows would.
    counters = {"fields": 0, "varint": 0, "64-bit": 0, "32-bit": 0, "length-delimited": 0, "nested_messages": 0,
                "text_values_withheld": 0, "bytes_values_withheld": 0, "nested_payloads_withheld": 0,
                "number_values_withheld": 0, "deepest": 0}
    serial = [0]
    fields = LosslessPage(TOOL, [source, offset, length, max_depth], limit, INLINE_BYTES) if window_accepted else None
    spans = {"text": "text", "bytes": "bytes", "nested": "nested_payload"}

    def locator(row, kind, size):
        return {"source": source_real, "field_path": row["field_path"], "offset": row["offset"],
                "payload_offset": row.get("payload_offset"), "kind": kind, "bytes": size}

    def put_rows(items):
        for row in items:
            children = row.pop("_children", None)
            span = row.pop("_span", None)
            counters["fields"] += 1
            counters[row["wire_type"]] += 1
            counters["deepest"] = max(counters["deepest"], row["depth"])
            if children:
                counters["nested_messages"] += 1
            row["source"] = source
            # A number is printed only when it is a top-level varint: under a length-delimited field it may be
            # the content of a string or of bytes read as a nested message, and a fixed-width value is raw bytes.
            if row["wire_type"] in ("varint", "64-bit", "32-bit") and (row["depth"] >= 1 or row["wire_type"] != "varint"):
                numbers = {k: row.pop(k) for k in NUMBER_KEYS if k in row}
                serial[0] += 1
                finding = "V%06d" % serial[0]
                row["finding_id"] = finding
                row["value_withheld"] = ("inside a length-delimited field, so it may be the content of a string or of bytes"
                                         if row["depth"] >= 1 else "a fixed-width value is raw bytes")
                counters["number_values_withheld"] += 1
                if values.enabled:
                    # Padded to one width: how many digits a withheld number has must not be the size of the file.
                    padding = NUMBER_WIDTH - len(dumps({**numbers, "pad": ""}))
                    values.add(finding, locator(row, "number", None), {**numbers, "pad": "-" * max(padding, 0)})
            if span:
                serial[0] += 1
                finding = "V%06d" % serial[0]
                row["finding_id"] = finding
                kind = span[0]
                counters[{"text": "text_values_withheld", "bytes": "bytes_values_withheld", "nested": "nested_payloads_withheld"}[kind]] += 1
                if values.enabled:
                    content = blob[span[1]:span[2]]
                    content = codecs.utf_8_decode(content, "replace", True)[0] if kind == "text" else content.hex()
                    values.add(finding, locator(row, spans[kind], span[2] - span[1]), content)
            fields.add(row)
            if children:
                put_rows(children)

    if window_accepted:
        put_rows(rows)
    elif values.enabled and blob:
        # What a window that is not a message failed on, for the job that asked for the values: the window itself, whole, as
        # hexadecimal, and the parser's finding in a fixed width. Not the rows the parse found: a file whose size follows the
        # number of fields would tell the requester what the window's bytes parse as.
        failed = window_rule_failed(blob, state, shape, aimed)
        found = {"state": state.ljust(11), "reason": ((problem or {}).get("reason") or "").ljust(REASON_WIDTH),
                 "offset": ("%020d" % problem["offset"]) if problem else "-" * 20, "rule_failed": failed.ljust(24)}
        assert len(found["reason"]) == REASON_WIDTH and len(found["rule_failed"]) == 24 and len(found["state"]) == 11, found
        serial[0] += 1
        values.add("V%06d" % serial[0], {"source": source_real, "field_path": None, "offset": offset, "payload_offset": None,
                                         "kind": "window", "bytes": len(blob), "parse": found}, blob.hex())
    values.close()
    page = fields.finish() if fields is not None else None
    if not blob:
        structure = {"status": "empty", "reason": "the window holds no bytes"}
    elif window_accepted and state == "ok":
        structure = {"status": "valid", "reason": "the whole window parsed as protobuf wire format and meets the acceptance rule"}
    elif window_accepted:
        structure = {"status": "partial", "reason": problem["reason"], "resume_offset": ctx.stop_at}
    else:
        # One status and one set of words for every window that is not accepted (a parse error, a group, too short, text,
        # unordered): which of them it was, and any count, come from the window's bytes.
        structure = {"status": "not_accepted",
                     "reason": "the window is not a message the rules show: it must parse whole, be at least %d bytes (%d when offset or length was given) with at "
                               "least two fields (%d when offset or length was given), not be entirely printable text, write shortest-form varints, "
                               "order its field numbers ascending and keep them at %d or below: no row, field number, varint or count is printed, since "
                               "what they show may be the bytes themselves"
                               % (MIN_WINDOW_BYTES, MIN_AIMED_BYTES, MIN_AIMED_FIELDS, NESTED_FIELD_MAX),
                     "rows_withheld": True}
    structure["bytes_in_window"] = len(blob)
    structure["consistent_with_protobuf_wire_format"] = bool(window_accepted and state == "ok")
    if window_accepted and ctx.depth_limited:
        structure["fields_not_tried_as_nested_at_max_depth"] = ctx.depth_limited
    # The answer is about the window it read. A window that is not the whole input leaves the rest undecoded, whatever the window itself
    # parsed as (structure says that, and consistent_with_protobuf_wire_format stays about the window): the status is complete only
    # when nothing lies after the window.
    after = window["bytes_after_window"]
    # No number in these words, and none for a window that is not shown: that answer is the same wherever the window lies (window says where).
    unread = " Bytes after the window are not decoded (window.bytes_after_window says how many, window.next_offset where the next window starts)." if after > 0 else ""
    if structure["status"] == "valid":
        if after > 0:
            status, status_basis = "partial", "this window parsed as protobuf wire format and meets the acceptance rule, but it is not the whole input." + unread
        else:
            status, status_basis = "complete", "the whole window parsed as protobuf wire format and meets the acceptance rule, and nothing lies after it"
    elif structure["status"] == "partial":
        status, status_basis = "partial", "a budget or the clock stopped the parse (resume_offset says where): " + structure["reason"] + unread
    elif structure["status"] == "empty":
        status, status_basis = "partial", "the window holds no bytes, so nothing was read" + unread
    else:
        # Not shown: the same words wherever the window lies, so nothing here depends on how far from the end of the input it is.
        status, status_basis = "partial", "no row is printed for this window (structure.status %s): " % structure["status"] + structure["reason"]
    send({
        "source": source,
        "parser": PARSER,
        "status": status,
        "status_basis": status_basis,
        "window": window,
        "structure": structure,
        "fields": fields.page if fields is not None else [],
        "field_count": counters["fields"],
        "top_level_fields": len(rows) if window_accepted else 0,
        "counts": counters,
        "limits": {"max_depth": max_depth, "max_fields": max_fields, "max_seconds": max_seconds, "inline_rows": limit,
                   "window_default_bytes": DEFAULT_WINDOW, "window_hard_cap_bytes": HARD_WINDOW},
        "pages": {"fields": page} if page is not None else {},
        "truncated": bool(page and page["truncated"]),
        "secret_values": values.summary(),
        "paths_withheld": PATHS_WITHHELD[0],
        "note": "This is wire structure, not meaning: no field name, unit, enum or signedness is known without the .proto "
                "file. Rows, field numbers and varints are printed only for a window that parses whole as a message "
                "(at least eight bytes and two fields, not entirely printable text, shortest-form varints, ascending field numbers, none above 300; "
                "sixteen bytes and four fields when offset or length was given); any other window, "
                "which includes one aimed at the payload of a field the answer withheld, gets one status (not_accepted) and no count (field_count, top_level_fields and "
                "counts are zero: they would come from its bytes), and its bytes are in the values file when write_values was asked for in a job run with secret_output: true. In a "
                "printed window a top-level varint is printed raw, with its zigzag reading (and, where the top bit is set, "
                "the two's-complement reading); nothing else that holds a value is: not the text of a string, not the bytes "
                "of a bytes field or the payload of a nested message, not a number under a length-delimited field, not a "
                "fixed-width value. Each has its offset, length and reading and a finding id. read_as is a guess between a "
                "nested message, text and bytes: printable text is always text, and a nested reading needs the acceptance "
                "rule; a binary value that is accepted shows that structure (field numbers, wire types, lengths), which is "
                "derived from its bytes: rare for a key or a token (about one random 16-byte value in 3,400), and not "
                "impossible. A window slid across a token is held to the stricter rule for a window with an offset or a length, and a "
                "residual remains: in a measurement on tokens that are the whole of one string field, 0 to 1.2 percent of 12- to 64-character tokens had a window "
                "that was shown, and at most 0.2 percent of a token's characters were derivable from it; for a token split across two fields or "
                "written as repeated six-byte pieces it is higher (up to 12.5 percent of 64-character hexadecimal tokens had a shown window, never a whole token); the same whatever max_fields is set to, since an aimed window that the field budget stopped is not shown. A group makes the window `not_accepted`, as does every other window the rules do not show. "
                "Offsets are absolute in the file.",
    })


if __name__ == "__main__":
    run_main(main)
