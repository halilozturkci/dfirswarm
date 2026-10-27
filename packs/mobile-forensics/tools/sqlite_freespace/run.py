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

WHAT `contains` DOES. It marks, and never drops. The values file holds a row for every fragment found, whatever the
expression says; `match` is 1 for a fragment it matched (and for every fragment when no expression was given), 0 for one it did
not match and 2 for one it could not decide (it ran out of time). The file's size does not depend on the expression, and nor
does the answer: a file that was shorter when the expression matched less would tell the requester, through its size, whether
text it cannot see matches. Rows carry a random `run`, so the file's digest is different in every run. What stays a function of
the hidden text is the file's size as JSON writes the text (a quote, a backslash, a control or non-ASCII character is escaped),
which no expression changes.

WHAT THE RUN TIME AND THE STATUS DO NOT SAY. An accepted expression costs a little more on text its first element matches than
on text it does not, so the time `contains` takes still follows the hidden text (measured: `\\d{250}x` on 22 fragments of 60,000
characters took 1.4 s of CPU on digits and 0.16 s on letters). That time is not allowed to reach the answer: the expression is given
a WORK BUDGET (STEP_BUDGET steps, fewer for a short max_seconds, one step being one character of a fragment times the expression's cost bound,
and FRAGMENT_STEPS more for every fragment it is called on, whatever its length: calling it costs time on a fragment of three characters
too; both are sizes the answer shows), a fragment that would exceed it is marked `match` 2 and counted, and the clock of `max_seconds` does
not run while the expression does. So `status`, `pages_not_reached` and `contains_not_decided` are functions of the visible sizes, the expression
and `max_seconds` against the tool's own work, never of the characters of the hidden text. What remains is the duration of the job
itself, which a requester can see: it follows the class composition of the hidden text, by at most the time the clock skips. That is
bounded: the work budget bounds it where the machine is as fast as measured (about 7 s of CPU, 10.5 s on a loaded one), and
EXPRESSION_ALLOWANCE bounds it where it is not, whatever the budget says: past it the clock runs again. A run with `contains` therefore
ends at max_seconds plus at most that allowance plus the time to write the answer, and the manifest's timeout leaves room for it.

The file is read-only to this tool: it is opened for reading, as bytes, and never written.

WHAT A REQUESTING AGENT CAN SEE. The answer, and the job's file list with each file's size and digest, are what a requester is shown
without asking. The values file itself is under store/ of the sandbox, which an agent's VM mounts read-only: an agent that opens it reads
every row, the values (and `match`) included. The measures above protect what is shown without anyone opening the file (the answer, its
status and counts, the file's size and digest). They do not stop an agent that deliberately opens the sealed file, and this tool does not
decide whether it may: that is the sandbox's mounts.
"""
import errno
import hashlib
import json
import math
import os
import re
import select
import signal
import struct
import sys
import tempfile
import time
import unicodedata
import warnings
from array import array
from pathlib import Path

try:  # Python 3.11 and later; the module was sre_parse before
    from re import _constants as sre_constants, _parser as sre_parse
except ImportError:  # pragma: no cover
    import sre_constants, sre_parse

PARSER = "sqlite_freespace/2"
TOOL = "sqlite_freespace"
VALUES_NAME = "sqlite-freespace-values.jsonl"
VALUES_FORMAT = ("JSON Lines, mode 0600, one row for every fragment found: finding_id, file (the real path), page, where, encoding, "
                 "offset, bytes, characters, match (1 matched `contains` or none was given, 0 did not match, 2 not decided), run "
                 "(random, the same in every row of this run), value (the fragment's text, whole)")


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

MAGIC = b"SQLite format 3\x00"
LOCK_BYTE_OFFSET = 1 << 30
DEFAULT_LIMIT = 200
DEFAULT_MAX_SECONDS = 240
MAX_SECONDS_CAP = 255       # manifest.json timeout_seconds (300) less EXPRESSION_ALLOWANCE, the lag of one fragment or page and the time to write the answer
INLINE_BYTES = 1 << 20
REGEX_SECONDS = 2.0         # one fragment: a pattern inside the cost bound below never gets near it (0.12 s at most on a whole page)
# The work `contains` may do in one run, in steps: a fragment of n characters under an expression whose cost bound is c is
# FRAGMENT_STEPS + n*c steps (the sizes the answer shows). A fragment that would take the total over it is not matched: it is marked 2
# and counted under contains_not_decided, the same on any text of the same sizes. The cost bound is an upper bound: the slowest accepted
# expression measured 7.3 ns a step, so the budget is about 7 s of CPU at the most on this kind of machine (10.5 s on a loaded one).
# FRAGMENT_STEPS is what calling the expression costs on a fragment of any length (the timer around it, the call, the search: 2.85 us
# measured, against 0.12 us for the bare search of a short fragment), 2.85 ns a step at 1,000 steps. Without it the characters of a
# fragment of three characters were 3 steps, the budget never bound, and a run of such fragments with max_seconds 270 took 327 s, the
# clock having skipped all the time of the calls. A short max_seconds lowers the budget (STEPS_PER_SECOND of max_seconds, at 20 ns a step), so that the run stays
# about as long as it was asked to be.
STEP_BUDGET = 1_000_000_000
STEPS_PER_SECOND = 50_000_000
FRAGMENT_STEPS = 1000
# The most the clock of max_seconds skips in all, whatever the work budget says and however slow the machine: a starved machine takes
# longer per step than the budget assumes, and the tool must still answer before the manifest's timeout (MAX_SECONDS_CAP is that
# timeout less this and the time to write the answer). Past it the clock runs while the expression does.
EXPRESSION_ALLOWANCE = 12.0
# `contains` runs only on text nobody can see, so how long it takes must not depend on that text. Python's re backtracks, and
# a pattern with nested repeats, a lookahead or a back reference can be made to run for seconds on a fragment that holds a
# guess and for microseconds on one that does not: one bit per call. Only patterns of a cost the tool can bound are accepted
# (see linear_pattern). The bound is small, not zero: an accepted expression still costs a little more on text that its first
# element matches than on text it does not. Measured on 32,768 characters, the slowest of 171 accepted candidate expressions (one
# class repeated 250 times, against text of that class) took 0.06 s of CPU, and 1.1 s when the bound was 16384; the time still
# follows the hidden text by that much per character, and at evidence volumes it adds up (1.4 s against 0.16 s on 1.3 MB of digits
# against letters). So the time of the expression never reaches the answer: it has a work budget (STEP_BUDGET) derived from visible
# sizes, and the clock that max_seconds is measured on stops while the expression runs. REGEX_SECONDS is only a stop for a machine
# that is starved (the largest fragment, a whole page, takes 0.12 s); a fragment it stops is marked 2 and counted like one that
# is over budget.
MAX_PATTERN_CHARS = 256
MAX_PATTERN_COST = 256
MAX_REPEAT_COUNT = 4096
PROBLEMS_INLINE = 200
PROBLEM_ROWS_PER_KIND = 100     # rows of one kind written one by one; the rest of that kind is one folded row (exact count, first and last place)
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


def linear_pattern(source):
    """(pattern, None, cost) for a `contains` expression whose matching cost the tool can bound, else (None, reason, 0).
    The cost is the bound on the steps from one start (ways times steps along a path), at least 1.

    Accepted: literals, classes, `.`, anchors and `\\b`, groups, alternation outside any repeat, and repeats of one
    deterministic piece with a finite upper bound (`{m,n}`, `?`). Refused: an unbounded repeat (`*`, `+`, `{m,}`),
    a repeat that holds a choice (a nested repeat or an alternation), lookahead and lookbehind, back references, conditionals,
    atomic groups and possessive repeats, and any pattern whose worst case (the number of ways it can match from one start
    times the work in each) is over MAX_PATTERN_COST. The reason names a construct, never the text.
    """
    if len(source) > MAX_PATTERN_CHARS:
        return None, "contains is at most %d characters" % MAX_PATTERN_CHARS, 0
    try:
        with warnings.catch_warnings():      # a FutureWarning ("possible nested set") would go to stderr
            warnings.simplefilter("ignore")
            tree = sre_parse.parse(source, re.I)
    except (re.error, RecursionError, OverflowError) as exc:
        return None, "contains is not a valid regex (%s)" % type(exc).__name__, 0
    unbounded = sre_constants.MAXREPEAT

    class Refused(Exception):
        pass

    def walk(items):
        """(ways, steps) for a sequence: the paths the engine may try from one start, and the work along one path."""
        ways, steps = 1, 0
        for op, av in items:
            name = str(op)
            if name in ("LITERAL", "NOT_LITERAL", "ANY", "IN", "AT"):
                w, st = 1, 1
            elif name == "SUBPATTERN":
                w, st = walk(av[3])
            elif name == "BRANCH":
                parts = [walk(branch) for branch in av[1]]
                w, st = sum(p[0] for p in parts), max(p[1] for p in parts)
            elif name in ("MAX_REPEAT", "MIN_REPEAT"):
                low, high, body = av
                if high == unbounded:
                    raise Refused("an unbounded repeat (*, + or {m,}) is not accepted: give it a bound, for example {1,64}")
                if high > MAX_REPEAT_COUNT:
                    raise Refused("a repeat count above %d is not accepted" % MAX_REPEAT_COUNT)
                body_ways, body_steps = walk(body)
                if low == high:
                    w, st = body_ways ** low if low else 1, body_steps * low
                else:
                    if body_ways != 1:
                        raise Refused("a repeat of a nested repeat or an alternation is not accepted")
                    w, st = high - low + 1, body_steps * high
            elif name in ("ASSERT", "ASSERT_NOT"):
                raise Refused("lookahead and lookbehind are not accepted")
            elif name in ("GROUPREF", "GROUPREF_EXISTS"):
                raise Refused("back references and conditionals are not accepted")
            else:
                raise Refused("this construct (%s) is not accepted" % name.lower())
            ways *= w
            steps += st
            if ways * max(steps, 1) > MAX_PATTERN_COST:
                raise Refused("the expression can take too many steps on a long fragment (its worst case is over %d); "
                              "shorten it, or bound its repeats lower" % MAX_PATTERN_COST)
        return ways, steps

    try:
        ways, steps = walk(tree)
    except Refused as why:
        return None, str(why), 0
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        return re.compile(source, re.I), None, max(1, ways * steps)


class OutOfTime(Exception):
    pass


def decode(raw, encoding):
    if encoding == "utf-8":
        return raw.decode("utf-8", "replace")
    return raw.decode("utf-16-le" if encoding == "utf-16le" else "utf-16-be", "replace")


ONE_MORE = bytes((i + 1) & 0xFF for i in range(256))


def take(taken, start, end):
    """Count the bytes of [start, end) as taken once more. `taken` holds, for every byte of the region, how many accepted runs
    contain it: runs of one encoding at one parity never overlap, so a byte is in at most one run per parity and one UTF-8 run."""
    taken[start:end] = taken[start:end].translate(ONE_MORE)


def covered_by(taken, start, end):
    """Whether half or more of the bytes of [start, end) are in runs already accepted (a byte in two of them counts twice, as it did
    when the runs were a list). A sum over a slice, not over every run accepted so far: a region of 8,191 fragments cost 7.4 s."""
    return sum(taken[start:end]) * 2 >= end - start


def runs_in(region, patterns, encodings, wide_minimum):
    """(start, end, encoding) of the text runs in `region`, and how many candidates were dropped.

    UTF-8 runs are taken first. A UTF-16 run is then taken when it is at least minimum units (a run that
    holds a wide unit must be wide_minimum), narrow runs before wide ones, and is dropped when half or more
    of its bytes are already in a run taken: printable ASCII read at the wrong parity is a run of wide
    units, and a UTF-8 text read as UTF-16 is the same.
    """
    found, taken = [], bytearray(len(region))
    for run in patterns["utf-8"].finditer(region):
        found.append((run.start(), run.end(), "utf-8"))
        take(taken, run.start(), run.end())
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
        if covered_by(taken, candidate[0], candidate[1]):
            dropped += 1
            continue
        found.append(candidate)
        take(taken, candidate[0], candidate[1])
    found.sort(key=lambda f: (f[0], f[2]))
    return found, dropped


def varint(data, at, end):
    """(value, length) of the SQLite varint at `at`, or (None, 0) when it runs past `end`."""
    value = 0
    for i in range(9):
        if at + i >= end:
            return None, 0
        byte = data[at + i]
        if i == 8:
            return (value << 8) | byte, 9
        value = (value << 7) | (byte & 0x7F)
        if not byte & 0x80:
            return value, i + 1
    return None, 0


def overflow_of(page, offset, kind, cells, usable):
    """([(first overflow page, pages in its chain)], cells that could not be read) for the cells of one b-tree page whose payload does
    not fit on it (the file format's "cell payload overflow pages"). A table leaf holds up to X = U-35 bytes of a payload of P bytes,
    an index page up to X = ((U-12)*64/255)-23; past X the cell keeps K = M+((P-M)%(U-4)) bytes if that is at most X, else M =
    ((U-12)*32/255)-23, and ends with the number of the first overflow page. A table interior page holds no payload.
    Most cells are told apart by their first byte, so a page of small rows costs one comparison a cell."""
    if kind == 5 or not cells:
        return [], 0
    maximum = usable - 35 if kind == 13 else (usable - 12) * 64 // 255 - 23
    minimum = (usable - 12) * 32 // 255 - 23
    skip = 4 if kind == 2 else 0                    # an index interior cell starts with its left child's page number
    spills, unreadable = [], 0
    for cell in struct.unpack_from(">%dH" % cells, page, offset + (12 if kind in (2, 5) else 8)):
        at = cell + skip
        if at >= usable:
            unreadable += 1
            continue
        if page[at] < 0x80 and page[at] <= maximum:
            continue
        size, length = varint(page, at, usable)
        if size is None:
            unreadable += 1
            continue
        if size <= maximum:
            continue
        at += length
        if kind == 13:                              # the row id follows the payload size in a table leaf
            _, length = varint(page, at, usable)
            if not length:
                unreadable += 1
                continue
            at += length
        local = minimum + (size - minimum) % (usable - 4)
        if local > maximum:
            local = minimum
        at += local
        if at + 4 > usable:
            unreadable += 1
            continue
        spills.append((int.from_bytes(page[at:at + 4], "big"), -(-(size - local) // (usable - 4))))
    return spills, unreadable


SERIAL_SIZES = {0: 0, 1: 1, 2: 2, 3: 3, 4: 4, 5: 6, 6: 8, 7: 8, 8: 0, 9: 0}


def schema_root(page, at, usable):
    """The `rootpage` of the sqlite_master row whose cell starts at `at` in a table leaf (0 for a view, a trigger or a virtual table), or
    None when the record cannot be read as far as that column (it is the fourth: type, name, tbl_name, rootpage, sql)."""
    size, length = varint(page, at, usable)
    if size is None:
        return None
    at += length
    _, length = varint(page, at, usable)
    if not length:
        return None
    at += length
    if size > usable - 35:                       # only the part of the record that is on the page is here
        minimum = (usable - 12) * 32 // 255 - 23
        local = minimum + (size - minimum) % (usable - 4)
        size = local if local <= usable - 35 else minimum
    end = min(at + size, usable)
    header, length = varint(page, at, end)
    if header is None or header > size:
        return None
    types, position = [], at + length
    while position < at + header and len(types) < 4:
        kind, length = varint(page, position, end)
        if kind is None:
            return None
        types.append(kind)
        position += length
    if len(types) < 4:
        return None

    def width(kind):
        if kind in SERIAL_SIZES:
            return SERIAL_SIZES[kind]
        return None if kind < 12 else (kind - 12) // 2 if kind % 2 == 0 else (kind - 13) // 2

    body = at + header
    for kind in types[:3]:
        if width(kind) is None:
            return None
        body += width(kind)
    kind = types[3]
    if kind in (0, 8):
        return 0
    if kind == 9:
        return 1
    if kind not in (1, 2, 3, 4, 5, 6) or body + width(kind) > end:
        return None
    return int.from_bytes(page[body:body + width(kind)], "big", signed=True)


# Problems that say the file's structure disagrees with itself. Any of them makes the status `corrupt`
# (the fragments found are still reported); a limit or a page or file not examined makes it `partial`.
CORRUPT_KINDS = {
    "file shorter than its header says", "partial last page", "freelist cycle", "freelist page outside the file",
    "freelist trunk page truncated", "freelist trunk count too large", "freelist page listed twice",
    "freelist count differs from the header", "b-tree page header inconsistent", "freeblock chain corrupt",
    "fragment not found at its offset", "pages in no structure", "b-tree cell outside its page", "b-tree links inconsistent",
    "pointer-map page not a pointer map",
    "pointer-map page not a pointer map",
}


class Problems:
    """What was not examined, or does not add up, each with where: a guard that stopped a walk is
    said, never silent."""

    def __init__(self, page):
        self.page = page
        self.unexamined = 0
        self.kinds = {}
        self.written = {}
        self.folded = {}

    def add(self, kind, detail, examined, **where):
        self.kinds[kind] = self.kinds.get(kind, 0) + 1
        if not examined:
            self.unexamined += 1
        if self.written.get(kind, 0) >= PROBLEM_ROWS_PER_KIND:
            # A file can make millions of problems of one kind (a leaf pointer outside the file, three thousand times a trunk page): the first rows
            # of a kind are written whole, and the rest is counted here, with where the first and the last of them were.
            fold = self.folded.setdefault(kind, {"count": 0, "first": where, "last": where, "examined": True})
            fold["count"] += 1
            fold["last"] = where
            fold["examined"] = fold["examined"] and examined
            return
        self.written[kind] = self.written.get(kind, 0) + 1
        self.page.add({"kind": kind, "detail": detail, "region_or_page_examined": examined, **where})

    def fold_rows(self):
        """One row for each kind that went past PROBLEM_ROWS_PER_KIND: how many more there were and the first and last place; problem_kinds has the exact total."""
        for kind, fold in self.folded.items():
            self.page.add({"kind": kind, "detail": "%d more problems of this kind are folded into this row (the first %d of the kind are above; problem_kinds has the total): "
                           "the first folded one at %s, the last at %s" % (fold["count"], PROBLEM_ROWS_PER_KIND, fold["first"] or "the file", fold["last"] or "the file"),
                           "folded": fold["count"], "first_folded_at": fold["first"], "last_folded_at": fold["last"], "region_or_page_examined": fold["examined"]})


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
    pattern, cost = None, 1
    if contains:
        if not isinstance(contains, str):
            fail("contains must be a regular expression")
        pattern, why, cost = linear_pattern(contains)
        if pattern is None:
            fail("contains is refused: " + why, contains_refused=True)
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
        freelist_stopped = False
        trunk, seen = h["freelist_head"], set()
        max_leaves = usable // 4 - 2
        while trunk:
            if trunk in seen:
                problems.add("freelist cycle", "trunk page %d is reached twice: the rest of the chain is not followed" % trunk, False, page=trunk)
                break
            if trunk < 2 or trunk > in_file:
                problems.add("freelist page outside the file", "the chain names page %d, and the file has %d pages" % (trunk, in_file), False, page=trunk)
                break
            if not trunks % 64 and time.monotonic() > deadline:
                freelist_stopped = True       # the scan below is stopped by the same clock at its first page, and says so (time limit, pages not reached)
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
        if not freelist_stopped and len(free) != h["freelist_declared"]:
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

        # A page at a pointer-map position holds 5-byte entries whose first byte is a type from 1 to 5 (0 for a page the file does not have): a header
        # that says auto-vacuum (bytes 52-55) over a page of anything else is not a pointer map, and skipping it would hide whatever the page holds.
        for position in sorted(pointer_maps):
            if position > in_file:
                continue
            walk.seek((position - 1) * page_size)
            raw = walk.read(page_size)
            if len(raw) == page_size and max(raw[0:(usable // 5) * 5:5]) > 5:
                pointer_maps.discard(position)
                problems.add("pointer-map page not a pointer map",
                             "page %d is where the header's auto-vacuum field puts a pointer map, and its entries are not (a type over 5): it is read as an ordinary page" % position,
                             True, page=position)

        counts = {"pages_in_file": in_file, "pages_examined": 0, "pages_not_btree": 0, "pages_corrupt": 0,
                  "pages_partial": 0, "lock_byte_pages_skipped": 0, "pointer_map_pages_skipped": 0,
                  "freelist_trunk_pages": 0, "freelist_leaf_pages": 0, "freeblocks": 0, "unallocated_gaps": 0,
                  "regions_scanned": 0, "bytes_scanned": 0, "fragments_found": 0,
                  "fragments_unverified": 0, "candidates_dropped_as_overlapping": 0, "pages_not_reached": 0,
                  "overflow_pages": 0, "pages_in_no_structure": 0}
        undecided = [0]            # fragments contains could not be decided on: marked 2 in the values file, said in the answer

        spent_in_expression = [0.0]     # the clock of max_seconds does not run while contains does: see STEP_BUDGET
        work = [0]
        step_budget = min(STEP_BUDGET, int(max_seconds * STEPS_PER_SECOND))

        def out_of_time():
            return time.monotonic() - min(spent_in_expression[0], EXPRESSION_ALLOWANCE) > deadline
        stopped_at = None
        serial = 0
        # A page that is not a b-tree page and not on the freelist is live content only if a cell names it as an overflow page.
        # One bit a page says which are named; `loose` lists the pages that are neither, to be set against it when the scan ends.
        named = bytearray((in_file >> 3) + 1)
        loose = array("I")
        unreadable_cells = 0

        def name_chain(head, pages):
            """Mark the pages of one overflow chain (each begins with the number of the next, 0 at the end)."""
            while head and pages:
                if not 2 <= head <= in_file or named[head >> 3] & (1 << (head & 7)):
                    return
                named[head >> 3] |= 1 << (head & 7)
                counts["overflow_pages"] += 1
                pages -= 1
                walk.seek((head - 1) * page_size)
                following = walk.read(4)
                if len(following) < 4:
                    return
                head = int.from_bytes(following, "big")

        def region_fragments(number, base_in_page, region, where, extra):
            nonlocal serial
            counts["regions_scanned"] += 1
            counts["bytes_scanned"] += len(region)
            found, dropped = runs_in(region, patterns, encodings, wide_minimum)
            counts["candidates_dropped_as_overlapping"] += dropped
            for start, end, encoding in found:
                if out_of_time():
                    raise OutOfTime()
                raw = region[start:end]
                text = decode(raw, encoding)
                characters = len(text)
                counts["fragments_found"] += 1
                # contains only marks the rows of the sealed values file (match 1, 0 or 2): every fragment is a row, so that the
                # file's size does not say how many matched. The answer lists every fragment whatever the expression says: a
                # list of the fragments that matched would answer, for each fragment, whether text you cannot see matches, and a
                # few hundred calls rebuild a token.
                hit = 1
                if pattern is not None:
                    work[0] += FRAGMENT_STEPS + characters * cost
                    if work[0] > step_budget:
                        hit = 2         # over the work budget: not decided, and the same for any text of these sizes
                        undecided[0] += 1
                    else:
                        began = time.monotonic()
                        try:
                            hit = 1 if timed_search(pattern, text, REGEX_SECONDS) is not None else 0
                        except Timeout:
                            hit = 2     # a starved machine: not decided, marked in the file, counted, and the answer says partial
                            undecided[0] += 1
                        spent_in_expression[0] += time.monotonic() - began
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
                values.add(finding, {"file": os.path.realpath(db), "page": number, "where": where, "encoding": encoding,
                                     "offset": absolute, "bytes": len(raw), "characters": characters, "match": hit}, text)

        def survey():
            """(reached, links, fan_out): the b-trees walked from the roots sqlite_master lists. `reached` is one bit a page, set for every page a
            walk arrives at (page 1 and the roots, then each interior page's children), or None when the schema cannot be read (or the walk is
            stopped by fan_out) and nothing can be said of which pages are in use; `links` counts the child pointers that leave the file and the
            pages two parents claim; `fan_out` says a b-tree held more child pointers than the file has pages, which no b-tree can: a page that
            is a child of two, or a cycle, and the walk stopped there.

            Nothing is kept per child: one pass over the file sets a bit for each interior page, and the walks read only those pages, each once
            (a page is marked when it is first named, and a page named again is a link problem, not another visit), under the clock."""
            interior = bytearray((in_file >> 3) + 1)
            scan.seek(0)
            for page_number in range(1, in_file + 1):
                if not page_number & 0xFF and out_of_time():
                    raise OutOfTime()
                raw = scan.read(page_size)
                if len(raw) < page_size:
                    break
                if (page_number in free or page_number in pointer_maps or (page_number == lock_page and file_bytes > LOCK_BYTE_OFFSET)
                        or (h["declared_size_valid"] and page_number > h["pages_declared"])):
                    continue
                start = 100 if page_number == 1 else 0
                if raw[start] in (2, 5) and start + 12 + struct.unpack_from(">H", raw, start + 3)[0] * 2 <= usable:
                    interior[page_number >> 3] |= 1 << (page_number & 7)
            seen = bytearray((in_file >> 3) + 1)
            links = 0
            budget = in_file               # a b-tree page has one parent: the child pointers of all the trees together are fewer than the pages
            stack = array("I")
            leaves = array("I")

            def name(child, collect):
                nonlocal links
                if not 1 <= child <= in_file or seen[child >> 3] & (1 << (child & 7)):
                    links += 1
                    return
                seen[child >> 3] |= 1 << (child & 7)
                if interior[child >> 3] & (1 << (child & 7)):
                    stack.append(child)
                elif collect:
                    leaves.append(child)

            def climb(collect):
                """Read the interior pages on the stack, naming their children. False when the pointers outnumber the pages."""
                nonlocal budget
                while stack:
                    n = stack.pop()
                    if out_of_time():
                        raise OutOfTime()
                    walk.seek((n - 1) * page_size)
                    raw = walk.read(page_size)
                    if len(raw) < page_size:
                        return True
                    start = 100 if n == 1 else 0
                    count = struct.unpack_from(">H", raw, start + 3)[0]
                    budget -= count + 1
                    if budget < 0:
                        return False
                    for cell in struct.unpack_from(">%dH" % count, raw, start + 12):
                        if cell + 4 <= usable:
                            name(int.from_bytes(raw[cell:cell + 4], "big"), collect)
                        else:
                            name(0, collect)       # a pointer that leaves the page: counted as a link outside the file
                    name(int.from_bytes(raw[start + 8:start + 12], "big"), collect)     # the right-most child
                return True

            # The roots: the rootpage column of every row of sqlite_master, a table b-tree that starts on page 1.
            name(1, True)
            if not climb(True):
                return None, links, True
            roots = array("I")
            for n in leaves:
                if out_of_time():
                    raise OutOfTime()
                walk.seek((n - 1) * page_size)
                raw = walk.read(page_size)
                start = 100 if n == 1 else 0
                if len(raw) < page_size or raw[start] != 13:
                    return None, links, False
                count = struct.unpack_from(">H", raw, start + 3)[0]
                if start + 8 + count * 2 > usable:
                    return None, links, False
                for cell in struct.unpack_from(">%dH" % count, raw, start + 8):
                    root = schema_root(raw, cell, usable)
                    if root is None:
                        return None, links, False
                    if root:
                        roots.append(root)
            for root in roots:
                name(root, False)
            if not climb(False):
                return None, links, True
            return seen, links, False

        scan.seek(0)
        number = 0
        stray = array("I")        # pages no structure owns
        try:
            number = 1
            reached, links, fan_out = survey()
            if fan_out:
                problems.add("b-tree links inconsistent", "the interior pages name more child pointers than the file has pages (%d), which no b-tree can: a page that two "
                             "pages name, or a cycle. The walk stopped there" % in_file, True)
            if reached is None:
                problems.add("b-tree reachability not established",
                             "sqlite_master could not be read to its end (a row, or a page of its b-tree, is damaged) or the walk was stopped: which pages "
                             "the b-trees own is not known, so a page that looks like a b-tree page is read as one and an orphaned page cannot be told", False)
            if links:
                problems.add("b-tree links inconsistent", "%d child pointer(s) of interior pages leave the file or name a page another pointer "
                             "already names" % links, True)
            scan.seek(0)
            for number in range(1, in_file + 1):
                if out_of_time():
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
                    loose.append(number)
                    continue
                if reached is not None and not reached[number >> 3] & (1 << (number & 7)):
                    # Looks like a b-tree page and no b-tree has it: a freed page the freelist does not list (its cells are as readable as
                    # a listed one's), or what is left of a b-tree whose parent is gone. The whole page is free space.
                    stray.append(number)
                    region_fragments(number, 0, page[:usable], "page in no structure (not reached by a b-tree, not listed free)", {})
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
                spills, bad = overflow_of(page, offset, kind, cells, usable)
                unreadable_cells += bad
                for head, pages in spills:
                    name_chain(head, pages)
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
            # What no structure owns: a page that is not a b-tree page, not on the freelist and named by no cell as an overflow page.
            # A freelist whose head and count are zeroed in the header hides every freed page this way.
            unowned = [n for n in loose if not named[n >> 3] & (1 << (n & 7))]
            for index, n in enumerate(unowned):
                stray.append(n)
                if out_of_time():
                    problems.add("time limit", "max_seconds (%s) passed while the pages no structure owns were being read: %d of the %d are not examined"
                                 % (max_seconds, len(unowned) - index, len(unowned)), False)
                    stopped_at = in_file
                    break
                walk.seek((n - 1) * page_size)
                try:
                    region_fragments(n, 0, walk.read(page_size)[:usable], "page in no structure (not a b-tree page, not listed free, not overflow)", {})
                except OutOfTime:
                    problems.add("time limit", "max_seconds (%s) passed in page %d, one of the pages no structure owns: %d of the %d are not fully examined"
                                 % (max_seconds, n, len(unowned) - index, len(unowned)), False, page=n)
                    stopped_at = in_file
                    break
            counts["pages_in_no_structure"] = len(stray)
            if unreadable_cells:
                problems.add("b-tree cell outside its page", "%d cell(s) of b-tree pages have a pointer or a length that leaves the page: "
                             "their overflow pages, if they have any, are not accounted for" % unreadable_cells, True)
            if stray:
                # Beside a -wal or a -journal that holds bytes the main file is a state between two checkpoints, and such pages are
                # expected: the status is partial for the companion already, and this is not read as the file disagreeing with itself.
                beside = any(suffix != "-shm" and info["bytes"] > 0 for suffix, info in companions.items())
                problems.add("pages in no structure" + (" beside a companion" if beside else ""),
                             "%d page(s) (the first: %s) are not owned by any structure: not on the freelist the header leads to, not reached by a "
                             "b-tree walked from sqlite_master, and not named by a cell as an overflow page. A freelist the header no longer leads to "
                             "(or a table dropped without its pages being freed) leaves pages like this. They are read as free space"
                             % (len(stray), ", ".join(str(n) for n in sorted(stray)[:5])), True)
        except OutOfTime:
            stopped_at = number
            counts["pages_not_reached"] = in_file - number + 1
            problems.add("time limit", "max_seconds (%s) passed in page %d: that page may be partly read, and pages %d to %d are not examined" % (max_seconds, number, number, in_file), False, page=number)
        if undecided[0]:
            problems.add("contains not decided", "contains was not decided on %d fragment(s) because the work its expression may do in one run was used up "
                         "(%d steps, a step being one character of a fragment times the expression's cost bound, and %d for every fragment the "
                         "expression is called on): they are rows of the values file marked match 2, as if they might have matched"
                         % (undecided[0], step_budget, FRAGMENT_STEPS), False)
            counts["contains_not_decided"] = undecided[0]
    values.close()
    problems.fold_rows()
    paging = {"fragments": fragments.finish(), "problems": problems.page.finish()}
    corrupt = any(kind in CORRUPT_KINDS for kind in problems.kinds)
    complete = problems.unexamined == 0 and stopped_at is None
    status = "corrupt" if corrupt else ("complete" if complete else "partial")
    if corrupt:
        status_basis = "the file's structure disagreed with itself where problems says; the fragments found are still reported"
    elif complete:
        status_basis = ("every page was accounted for (b-tree and free pages were read; the others are overflow pages that a cell names, pointer-map "
                        "pages or the lock-byte page), nothing in the structure was inconsistent and no companion was left unread")
    else:
        why = []
        if stopped_at is not None:
            why.append("the time limit stopped the scan before page %d" % stopped_at)
        if problems.unexamined:
            why.append("%d region(s), pages or companions were not examined (see problems)" % problems.unexamined)
        status_basis = "partial because " + "; ".join(why or ["part of the file was not examined (see problems)"])
    send({
        "db": shown(db),
        "parser": PARSER,
        "status": status,
        "status_basis": status_basis,
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
        "filter_marks": ("the rows of the values file only: every fragment is a row there, with match 1 (matched), 0 (did not) or 2 (not decided "
                         "in time, counted under problems); the fragments listed here are all of them, whatever the expression matched") if contains else None,
        "pages": paging,
        "companions": companions,
        "secret_values": ({**values.summary(), "rows_are_all_fragments": "match marks the rows contains matched; how many matched is not shown"}
                          if pattern is not None else values.summary()),
        "paths_withheld": PATHS_WITHHELD[0],
        **({"paths_note": "A path component shaped like a recovery password (a key split across components included), or a path too long to judge, is withheld from every path in this answer and in "
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
                "contains is accepted only with write_values: it marks the rows of the sealed values file (match 1 matched, 0 did not, 2 "
                "was not decided in time; every fragment is a row, so the file's size does not depend on the expression), and the list in this "
                "answer is every fragment whatever it matched (how many matched is not shown), since a list of the "
                "matches would answer, fragment by fragment, whether text you cannot see matches. contains is accepted only as an expression "
                "of bounded cost (no unbounded repeat, no nested repeat, no lookaround, no back reference, at most 256 steps): how long "
                "it runs on text you cannot see should not tell you about the text; the bound keeps what remains small, and does not make it zero: the "
                "duration of the job still follows how much of the hidden text is of a class the expression matches (1.4 s of CPU against 0.16 s on "
                "1.3 MB of digits against letters for one expression, and more at larger volumes, up to the time the work budget takes, about 7 s of CPU), "
                "and the page, the sizes and the status do not. The expression is given a work budget (a step is a character of a fragment times the "
                "expression's cost bound, and " + str(FRAGMENT_STEPS) + " for every fragment it is called on, all visible here), and the clock of max_seconds does "
                "not run while it runs, for " + str(EXPRESSION_ALLOWANCE) + " seconds at most in all; a fragment over the budget is marked 2 "
                "and counted under contains_not_decided, and the status is partial: the same for any text of these sizes. Status is complete (every page accounted for: "
                "b-tree and free pages read, the rest overflow pages that a cell names, nothing inconsistent, no companion left unread), "
                "partial (a limit, a companion not read, or pages or regions not examined) or corrupt (the file's "
                "structure disagreed with itself where problems says; the fragments found are still reported, and "
                "a corrupt chain means text beyond it was not reached). A fragment is a candidate to corroborate, "
                "never a message.",
    })


if __name__ == "__main__":
    run_main(main)
