#!/usr/bin/env python3
"""A preview of a HEIC or HEIF original, tied back to the original, with a bounded walk of its ISO-BMFF boxes.

Three things, each from a different source, never mixed:

  The original, by itself. Its size and SHA-256, and a walk of its boxes in the standard library, without a decoder: the `ftyp`
  brands (heic, heix, mif1, msf1 are the ones this reads), and under `meta` the handler (`hdlr`), the primary item (`pitm`), the
  items (`iinf`, `infe`) with their types and whether they are hidden, where their data is (`iloc`), the properties
  (`iprp`/`ipco`/`ipma`: the size `ispe`, the rotation `irot`), the references between items (`iref`: the tiles of a grid, the
  thumbnails) and, for a `grid` item, its rows, columns and output size from the item's own data. A hostile box (a size of 0 that
  runs to the end, a size past its parent or the file, a size smaller than its header, counts far beyond what the box can hold,
  nesting) is bounded and reported as a problem with its offset; the walk stops at MAX_BOXES boxes and says so. Every box and every
  problem is a line of a result file the answer names (nothing is cut): the inline answer is a prefix.

  The metadata, from the original with exiftool, and from nowhere else: the preview's own metadata never stands in for it. The
  answer carries the presence and the count of tags per group (EXIF, XMP, GPS, ...) and no value; the values (a position, a device
  serial, a time) are written only on `write_values: true`, only in a job run as secret output (SECRET_OUTPUT=1), to a 0600 file under
  $OUT created exclusively; otherwise the request is refused as JSON before anything is made.

  The preview, from ONE backend per run, recorded: `heif-convert` (the libheif example program) or `pillow-heif` (a Python library,
  run in a child process of its own, never in this process). There is no fallback: a backend that is not there is said, and the walk
  and the metadata are still given. Before the backend is started the original's size and the pixel count its own `ispe` declares
  are checked against max_bytes and max_pixels and a conversion past either is refused (a decompression-bomb guard); an original with
  no readable size cannot pass it and is refused too. The program runs in this tool's process group, never a session of its own,
  with the kernel asked to end it if the tool dies; its output goes to files that are watched, and at the deadline or past the
  output caps it and what it started are ended. The preview is written under $OUT/heic_inspect, never replacing a file.

The preview file is picture content and may carry the original's EXIF if the backend writes it: it is output
of the job like any other, and a job over pictures the case treats as sensitive runs with secret_output: true.
"""
import base64
import errno
import hashlib
import json
import math
import os
import re
import select
import shutil
import signal
import stat
import struct
import subprocess
import sys
import tempfile
import time
import unicodedata
from pathlib import Path

PARSER = "heic_inspect/5"
TOOL = "heic_inspect"
VALUES_NAME = "heic-inspect-values.jsonl"       # the first free name of this and -2, -3 ... is used (see choose_values_name)
VALUES_FORMAT = "JSON Lines: one metadata tag of the original per line (group, tag, value)"




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

# A stop that arrives while the rest of this module is still being read (the definitions below, the tool's own code after
# the block) is answered here, by one JSON document and exit 128 + the signal, as run_main answers it later. The handlers are
# installed as the module reaches this point, not when main() starts, so the window left is the interpreter's own start-up and
# the imports above the block, which no code in this file can close and which this tool does not claim: a stop there ends the
# process with no answer, before anything was read or written. run_main replaces these handlers.
EARLY_SIGNALS = [getattr(signal, name) for name in ("SIGTERM", "SIGINT", "SIGHUP") if hasattr(signal, name)]


def early_stop(signum, frame):
    for number in EARLY_SIGNALS:
        signal.signal(number, signal.SIG_IGN)
    name = signal.Signals(signum).name
    text = json.dumps({"error": "the tool was stopped by %s before it finished: this is not an answer to the question" % name,
                       "status": "failed", "status_basis": "stopped by %s before the tool had started to read anything" % name,
                       "interrupted": name}) + "\n"
    try:
        os.write(1, text.encode("utf-8"))
    except OSError:
        pass
    os._exit(128 + signum)


for early_number in EARLY_SIGNALS:
    signal.signal(early_number, early_stop)

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
WRITE_CHUNK = 4096


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
    # One os.write on a blocking pipe returns only when everything it was given has gone in, however slowly the reader takes it,
    # so a single call for the whole document would restart the clock once. A write of at most WRITE_CHUNK bytes (a pipe takes
    # up to PIPE_BUF bytes in one piece) returns when that much has been taken, so the clock restarts on every chunk the reader
    # takes and only a reader that takes nothing for WRITE_STALL_SECONDS is given up on.
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
                data = data[os.write(descriptor, data[:WRITE_CHUNK]):]
            except BlockingIOError:      # a pipe set non-blocking by its owner and full: wait until it can take more
                select.select([], [descriptor], [], 1.0)
    except OSError:       # the reader went away: there is nobody to answer
        raise SystemExit(1)
    finally:
        if timed:
            signal.setitimer(signal.ITIMER_REAL, 0)


def fail(message, **extra):
    answer = {"error": scrub(str(message)), "status": "failed", "status_basis": "the tool stopped with an error: %s" % scrub(str(message)),
              **{k: (scrub(v) if isinstance(v, str) else v) for k, v in extra.items()}}
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

# BEGIN SHARED PLACE
# The same text is in every windows-forensics tool that keeps a result file (a windows-forensics test holds the copies equal).
# A result file that is there is never replaced by another result: a file of the same bytes is named again, any other result takes the next free
# <stem>-<n><suffix>. A result written at the same moment cannot be replaced either: taking a name fails when it is there.
# Only regular files are ever compared: both names are opened with O_NONBLOCK and O_NOFOLLOW and looked at with fstat before a byte is
# read, so a FIFO, a device, a directory or a link at a name (the caller's own results_to, say) is another result's and cannot hold the
# tool. The comparing of one call has PLACE_COMPARE_SECONDS in all; past it an earlier result is taken as different and this one takes
# the next free name (nothing is replaced, but an identical rerun may then be named anew).
# The name is taken with a hard link of the finished file, so it never holds an empty file, whatever stops the tool and when (SIGKILL
# included). Where the file system refuses the link, the name is taken with an exclusive create and the file is moved over it: a stop
# that unwinds (an exception) takes the empty name back while it is still the empty file this call made; a stop that ends the process
# without unwinding (SIGKILL, the handlers of the STOP block) between the create and the move leaves the empty name, and the next run takes -2.
PLACE_COMPARE_SECONDS = 5   # all the comparing one call to place_without_replacing does; past it an earlier result is taken as different


def same_bytes(a, b, deadline=None):
    """Whether two files hold the same bytes (read in blocks, never whole). Each is opened without waiting and without following a link
    (O_NONBLOCK, O_NOFOLLOW) and looked at with fstat first: only two regular files of one size are read, so a FIFO, a device, a
    directory or a link at either name is never read (a FIFO would hold the tool for ever). Past `deadline` (a monotonic time) the
    answer is False."""
    flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOFOLLOW", 0)
    fa = fb = None
    try:
        fa = os.fdopen(os.open(str(a), flags), "rb")
        fb = os.fdopen(os.open(str(b), flags), "rb")
        sa, sb = os.fstat(fa.fileno()), os.fstat(fb.fileno())
        if (sa.st_mode & 0o170000) != 0o100000 or (sb.st_mode & 0o170000) != 0o100000 or sa.st_size != sb.st_size:
            return False
        while True:
            if deadline is not None and time.monotonic() > deadline:
                return False
            x, y = fa.read(1 << 20), fb.read(1 << 20)
            if x != y:
                return False
            if not x:
                return True
    except OSError:
        return False
    finally:
        for fh in (fa, fb):
            if fh is not None:
                fh.close()


def _take_name(tmp, candidate):
    """Give the finished `tmp` the name `candidate` if it is free, and say whether it now has it (False: the name is taken, by a file, a
    link, a FIFO or a directory). The name is taken with a hard link, so it never holds an empty file; where the file system refuses the
    link it is taken with an exclusive create and the file is moved over it, and a stop that unwinds in between takes the empty name back."""
    try:
        os.link(tmp, candidate)
    except FileExistsError:
        return False
    except OSError:
        pass                                   # no hard links here: the older way, below
    else:
        try:
            os.unlink(tmp)
        except OSError:
            pass                               # the hidden name stays beside the placed file; the stop path of the page removes it
        return True
    fd = made = None
    try:
        fd = os.open(str(candidate), os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        made = os.fstat(fd)
        closing, fd = fd, None
        os.close(closing)
        os.replace(tmp, candidate)             # only replaces the empty file this call just made
        return True
    except FileExistsError:
        return False
    except BaseException:
        try:
            if made is None and fd is not None:
                made = os.fstat(fd)
        except OSError:
            pass
        try:
            if fd is not None:
                os.close(fd)
        except OSError:
            pass
        try:
            now = os.lstat(candidate)
            if made is not None and (now.st_mode & 0o170000) == 0o100000 and now.st_size == 0 and (now.st_dev, now.st_ino) == (made.st_dev, made.st_ino):
                os.unlink(candidate)           # the empty name this call took is not left behind
        except OSError:
            pass
        raise


def place_without_replacing(tmp, path):
    """Move the finished `tmp` to `path` and never replace what is there. A name that is taken (by a file, a link, a FIFO or a directory) is
    left as it is: a regular file of the same bytes is named again, any other result takes the next free <stem>-<n><suffix>. Returns the
    path that holds it. The comparing with earlier results has PLACE_COMPARE_SECONDS in all: past it an earlier result is taken as
    different and this one takes the next free name."""
    deadline = time.monotonic() + PLACE_COMPARE_SECONDS
    for n in range(1, 1000):
        candidate = path if n == 1 else path.with_name("%s-%d%s" % (path.stem, n, path.suffix))
        if _take_name(tmp, candidate):
            return candidate
        if not os.path.islink(candidate) and same_bytes(tmp, candidate, deadline):
            os.unlink(tmp)
            return candidate
    raise OSError("no free name beside %s" % path)
# END SHARED PLACE

# BEGIN SHARED PROCESS
# The same text is in pcap_extract, zeek_run, suricata_run, the network-capture recipe and computer-forensics-base's
# archive_extract; tests/pack-network-withholding.test.ts holds the four network copies equal and tests/pack-base-shared.test.ts
# holds archive_extract's to them. A program an engine tool runs is started in THIS tool's process group, never in a session of
# its own: the harness ends a tool that runs too long, or is aborted, by killing the tool's group (process.kill(-pid,
# SIGKILL)), and an engine in a group of its own goes on writing into the output directory after the tool is gone. On
# Linux the kernel is also asked to kill it if the tool dies. A deadline kills the program and what it started by
# walking the process tree, and SIGTERM, SIGINT and SIGHUP do the same and then give the tool a last word. Only what is
# below a program this tool started and has not yet waited for is ever signalled: the walk starts at that program's pid
# and nowhere else, and a program that has been waited for (its pid may be another process's by now) is left alone. The
# walk is bounded (MAX_ROUNDS and WALK_SECONDS, below). A stop signal is the one case that reaches further: it also
# ends everything below the tool itself (a program that was forked a moment before it was entered in ACTIVE is among it) and what
# the tool started and lost (reap_orphans): a process that was seen below the tool, in the tool's own group, and whose parent has since
# ended. Nothing else is ever ended: a process the tool never saw in its tree (the next stage of a pipeline the tool heads, a process a
# launcher put in the group) is left alone, whoever leads the group. A program that has ended while something it started still
# holds its pipes does not hold the tool: communicate_bounded gives the pipes PIPE_GRACE seconds (and POST_EXIT_BYTES bytes) and goes on without them.
# The walk below a program is bounded: MAX_ROUNDS rounds and WALK_SECONDS seconds. Each process is stopped (SIGSTOP) as the walk finds it,
# so one that forks fast cannot outrun the walk; the walk is repeated for what the stopped ones had already forked, and the stopped set is
# then killed. A tree that is still growing at the bound is left, and process_notes() says so.
# Before a pid other than the program itself is signalled, its identity is read again (same_process(pid, ident)): the start time, from
# /proc/<pid>/stat (field 22, counted after the last ")") on Linux, from libproc's PROC_PIDTBSDINFO (pbi_start_tvsec, pbi_start_tvusec;
# written from <sys/proc_info.h>, not run on macOS in this repository's tests) on macOS, and from `ps -o lstart=` (to the second: coarse)
# where neither answers. The parent is no part of it: a child is re-parented when its parent ends, and is still the process that was
# listed. A pid that is gone, or whose start time is not the listed one, is left alone; a pid whose start time could not be read when it
# was listed is signalled only if it can be read now and is in the tool's own group; a ps listing that gave no start time (a minimal ps) is
# checked only for the pid still being there.
# A tree that cannot be listed (ps fails, lists nothing or needs more than PS_WAIT seconds, /proc cannot be read or takes more than
# TABLE_SECONDS) is never taken as an empty one: list_descendants raises TreeNotListed, the program itself is still ended, and a sentence
# in process_notes() says that the tree could not be listed (communicate_bounded also appends it to the stderr bytes it returns when it
# ended the program at its deadline). descendants() is list_descendants for a caller that cannot take an exception (a signal handler): its
# list is empty and has not_listed = True when the tree could not be listed.
# Open: a pid that ends and is reused between the identity check and the signal (two calls) is signalled; the Linux rule that a member of
# the tool's own group that holds the tool's pipe is ended; on macOS a daemon that holds the pipes of a finished program is not found (no
# /proc/<pid>/fd); a tool SIGKILLed between the stop and the kill leaves the program and the stopped set stopped (the harness ends the
# tool's group, and with it the stopped ones that are in it); a carrier's answer carries program_group (process_verdict, process_notes)
# only where that carrier's own code calls process_apply (without the call a program's leftovers are ended but not reported); the start of the interpreter, before any handler is in, is a window a signal can land in.
# What a program leaves behind (settle). A program can exit by itself and leave a process that goes on writing a file the answer then reports:
# one in a session of its own, or one that holds none of the tool's descriptors, which neither the walk nor the pipes reach. On Linux spawn()
# makes the tool a subreaper (become_subreaper, PR_SET_CHILD_SUBREAPER): such a process is adopted by the tool, so it is a direct child of the
# tool, and settle() ends it: when a program leaves ACTIVE after it has ended or been killed (ACTIVE is a list whose remove() does it), and at
# the end of communicate_bounded and inside kill_all. It ends only a child of the tool that is no program's own: not a program spawn() started
# (SPAWNED: Popen reaps those, their returncode is never taken), not one kept (KEEP, process_keep(pid), spawn(argv, leaves=True) for a
# program that leaves a process on purpose) and not a child the tool already had (PRE_KIDS). It stops each one, what it started with it (the
# walk above), kills and reaps them, for at most LEFTOVER_SECONDS, reading the clock for every process. While another program is running in
# ACTIVE nothing is ended and the answer says it is unproven. process_verdict() says what was found; process_apply(answer) puts it into an
# answer as program_group and turns a complete answer partial when a program left something or that could not be ruled out: a carrier
# calls it once where it prints its answer. Where nothing is adopted (not Linux, or the kernel refuses) settle() ends only what the tool saw
# below a program whose parent is gone, and the answer is unproven (NONLINUX_UNPROVEN_DOWNGRADE below is the one line that decides whether
# that alone makes a complete answer partial on a host that is not Linux). Not reached by any of this: a process that is not a descendant of
# a program (started through a service manager, a socket, another PID namespace), and the tool itself being killed (the harness ends its group).
# What a program's pipes deliver after it ended (the byte cap). communicate_bounded reads the pipes itself (a selector, not
# Popen.communicate) and looks at the program after every read. From the moment the program has ended, or been killed at its deadline, it
# takes at most POST_EXIT_BYTES (1 MiB) more bytes from its two pipes together and at most PIPE_GRACE seconds, whichever comes first; a
# program's own last words are in the pipe already (a pipe holds far less than the cap), so only what a process that went on holding the
# pipe wrote can be cut. At the cap the tool stops reading, ends the holder (reap_orphans, settle) and lets the pipes go: PIPE_CUT["cut"]
# counts the calls cut that way, process_notes() says so, and process_apply turns a complete answer partial. The bytes kept are the ones
# read, not a whole stream: a caller that parses the output sees the program's output and at most 1 MiB of what a leftover wrote. While the
# program is still alive nothing is capped here (a program's own output is its caller's to bound); the timing is unchanged.
import select as _select
import selectors as _selectors
import time

try:
    import ctypes
except ImportError:  # pragma: no cover
    ctypes = None

STATE = {"last_word": None}    # what to do, with the signal number, when the tool is stopped by a signal
class _Active(list):
    """The programs running now. A program that leaves the list after it has ended or been killed (a carrier removes it when it has waited
    for it) is followed by settle(): what it left behind is ended before the carrier reads what the program wrote. One that is still
    running when it is removed is not looked at."""

    def remove(self, proc):
        list.remove(self, proc)
        if proc.poll() is not None:
            settle()


ACTIVE = _Active()             # the programs running now
SPAWNED = {}                   # the programs spawn() started: pid -> identity (Popen reaps them, settle() never does)
KEEP = {}                      # the processes left on purpose: pid -> identity (settle() leaves them)
PRE_KIDS = {}                  # the children the tool already had when the first program was spawned: pid -> identity
LEAVES = {}                    # the programs started with leaves=True that have not ended yet: pid -> Popen
LEFT = {"left_behind": 0, "unproven": []}   # how many live processes settle() ended, and why nothing-left-behind cannot be proven
SUB = {"tried": False, "on": False, "note": None}        # whether the subreaper was asked for, and is on
SETTLING = [False]             # settle() is running (the stop signal's own call goes through)
LEFTOVER_SECONDS = 3              # the most one settle() works, in seconds; the clock is read for every process it ends, not once per pass
SETTLE_LOOK = 0.05             # the pause before the look that follows an ending: a fork that was under way when the first process died
# The one line the owner decides: on a host that cannot adopt orphaned processes (not Linux) a program may have left a process nobody can find.
# True: that alone is `unproven`, and process_apply turns a complete answer partial. False: the answer only carries a note.
NONLINUX_UNPROVEN_DOWNGRADE = True
SEEN = set()                   # the pids seen below a program this tool started: the only ones reap_orphans may end once their parent is gone
SEEN_IDENT = {}                # what each pid in SEEN was (its start time) when it was seen below the tool: a pid that ended and was reused does not match
NOTES = []                     # what this block could not do, as sentences for an answer (process_notes())
MAX_ROUNDS, WALK_SECONDS = 8, 15   # the bound of the walk below a program: rounds, and seconds
TABLE_SECONDS = 10             # the longest reading of /proc (or of a process table) is given
SEEN_MAX = 1 << 16             # the most pids SEEN holds

def _die_with_parent():  # runs in the child between fork and exec
    try:
        ctypes.CDLL(None).prctl(1, signal.SIGKILL)   # PR_SET_PDEATHSIG
    except Exception:  # noqa: BLE001
        pass


def spawn(argv, leaves=False, **kwargs):
    kwargs.setdefault("stdin", subprocess.DEVNULL)
    become_subreaper()
    if sys.platform.startswith("linux") and ctypes is not None:
        kwargs["preexec_fn"] = _die_with_parent
    proc = subprocess.Popen(argv, **kwargs)
    SEEN.add(proc.pid)
    started = _read_ident(proc.pid, "proc" if os.path.isdir("/proc/self") else "libproc")
    if started is not None:
        SEEN_IDENT[proc.pid] = started
    SPAWNED[proc.pid] = started
    if leaves:
        LEAVES[proc.pid] = proc     # what this program leaves behind stays (settle() keeps it)
    return proc


class TreeNotListed(Exception):
    """The processes could not be listed: ps failed, listed nothing or needed more than PS_WAIT seconds, /proc could not be read, or reading
    it took more than TABLE_SECONDS. It is never to be read as a tree with nothing below it."""


class _Listing(list):
    """The pids below a process, as a list; .ident holds each pid's identity from the same reading, .not_listed says the tree could not be listed."""
    ident = None
    not_listed = False


class _Table(dict):
    """{pid: (parent pid, process group)}; .ident holds each pid's identity from the same reading."""
    ident = None


def _note(text):
    """Record a sentence about what this block could not do (once, at most 20) and return it."""
    if text not in NOTES and len(NOTES) < 20:
        NOTES.append(text)
    return text


def process_notes():
    """What this block could not do so far, as sentences (a tree that could not be listed, a walk that was cut), for an answer."""
    return list(NOTES)


def _libproc_start(pid):
    """(seconds, microseconds) of the start of `pid` from libproc's PROC_PIDTBSDINFO (macOS), or None. Written from <sys/proc_info.h>
    (struct proc_bsdinfo, 136 bytes, flavor 3); not run on macOS in this repository's tests."""
    try:
        import ctypes.util

        class BsdInfo(ctypes.Structure):
            _fields_ = [("pbi_flags", ctypes.c_uint32), ("pbi_status", ctypes.c_uint32), ("pbi_xstatus", ctypes.c_uint32),
                        ("pbi_pid", ctypes.c_uint32), ("pbi_ppid", ctypes.c_uint32), ("pbi_uid", ctypes.c_uint32),
                        ("pbi_gid", ctypes.c_uint32), ("pbi_ruid", ctypes.c_uint32), ("pbi_rgid", ctypes.c_uint32),
                        ("pbi_svuid", ctypes.c_uint32), ("pbi_svgid", ctypes.c_uint32), ("rfu_1", ctypes.c_uint32),
                        ("pbi_comm", ctypes.c_char * 16), ("pbi_name", ctypes.c_char * 32), ("pbi_nfiles", ctypes.c_uint32),
                        ("pbi_pgid", ctypes.c_uint32), ("pbi_pjobc", ctypes.c_uint32), ("e_tdev", ctypes.c_uint32),
                        ("e_tpgid", ctypes.c_uint32), ("pbi_nice", ctypes.c_int32), ("pbi_start_tvsec", ctypes.c_uint64),
                        ("pbi_start_tvusec", ctypes.c_uint64)]

        lib = ctypes.CDLL(ctypes.util.find_library("proc") or "/usr/lib/libproc.dylib", use_errno=True)
        lib.proc_pidinfo.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_uint64, ctypes.c_void_p, ctypes.c_int]
        lib.proc_pidinfo.restype = ctypes.c_int
        info = BsdInfo()
        if lib.proc_pidinfo(pid, 3, 0, ctypes.byref(info), ctypes.sizeof(info)) != ctypes.sizeof(info):
            return None
        return (int(info.pbi_start_tvsec), int(info.pbi_start_tvusec))
    except Exception:  # noqa: BLE001 - no library, no symbol, a sandbox: the caller falls back
        return None


def _ps_start(pid):
    """The start time `ps -o lstart= -p <pid>` prints, to the second (coarse), or None when ps fails, takes more than PS_WAIT seconds or prints none."""
    try:
        done = subprocess.run(["ps", "-o", "lstart=", "-p", str(pid)], capture_output=True, text=True, timeout=PS_WAIT)
    except (OSError, subprocess.SubprocessError):
        return None
    text = " ".join(done.stdout.split())
    return text if done.returncode == 0 and text else None


def _read_ident(pid, kind):
    """The identity of `pid` read the way `kind` ("proc", "libproc" or "ps") says, or None when the process is gone or the way fails."""
    if kind == "proc":
        try:
            with open("/proc/%d/stat" % pid, "rb") as fh:
                data = fh.read()
            return ("proc", int(data[data.rindex(b")") + 2:].split()[19]))   # field 22, counted after the last ")": the name may hold one
        except (OSError, ValueError, IndexError):
            return None
    if kind == "libproc":
        started = _libproc_start(pid)
        return None if started is None else ("libproc", started)
    started = _ps_start(pid)
    return None if started is None else ("ps", started)


def process_ident(pid):
    """What tells the process that has `pid` now from a later one that gets the same pid: its start time. Linux: field 22 of /proc/<pid>/stat;
    macOS: libproc's pbi_start_tvsec and pbi_start_tvusec; where neither answers, the start time ps prints (to the second). The parent is no
    part of it: a child is re-parented when its parent ends, and is still the process that was listed. None where the process is gone or
    cannot be read."""
    if os.path.isdir("/proc/self"):
        return _read_ident(pid, "proc")
    return _read_ident(pid, "libproc") or _read_ident(pid, "ps")


def same_process(pid, ident):
    """Whether `pid` is still the process `ident` was read from (process_ident, or the listing a walk made): a pid that is gone, or that
    another process has taken since (another start time), is not. An `ident` of None (it could not be read when the process was listed) is
    not vouched for either: the pid is signalled only if it can be read now and is in this process's own group. A listing by plain ps that
    gave no start time ("listed") can only be checked for the pid still being there."""
    if ident is None:
        try:
            return process_ident(pid) is not None and os.getpgid(pid) == os.getpgrp()
        except OSError:
            return False
    if ident[0] == "listed":
        try:
            os.kill(pid, 0)
        except PermissionError:
            return True
        except OSError:
            return False
        return True
    return _read_ident(pid, ident[0]) == ident


def _seen_below(pids, ident):
    """Enter pids seen below the tool in SEEN, with the identity the listing that showed them gave."""
    for pid in pids:
        if pid in SEEN or len(SEEN) < SEEN_MAX:
            SEEN.add(pid)
            if ident.get(pid) is not None:
                SEEN_IDENT[pid] = ident[pid]


def _ps_rows(columns):
    """The rows of `ps -A -o <columns>` as lists of fields. Raises TreeNotListed when ps cannot be run, fails, takes more than PS_WAIT seconds
    or lists nothing."""
    try:
        done = subprocess.run(["ps", "-A", "-o", columns], capture_output=True, text=True, timeout=PS_WAIT)
    except subprocess.TimeoutExpired as exc:
        raise TreeNotListed("ps took more than %d seconds" % PS_WAIT) from exc
    except (OSError, subprocess.SubprocessError) as exc:
        raise TreeNotListed("ps could not be run: %s" % type(exc).__name__) from exc
    rows = [line.split() for line in done.stdout.splitlines() if line.split()]
    if done.returncode != 0 or not rows:
        raise TreeNotListed("ps %s" % ("exited %d" % done.returncode if done.returncode != 0 else "listed nothing"))
    return rows


def _children_libproc(pid):
    """The direct children of `pid` on macOS, from libproc (macOS only: proc_listchildpids is not a symbol of the other
    BSDs; a library call, so no program is started and nothing can be slow); None when the library, the symbol or the
    call is not there."""
    try:
        import ctypes.util
        lib = ctypes.CDLL(ctypes.util.find_library("proc") or "/usr/lib/libproc.dylib", use_errno=True)
        lib.proc_listchildpids.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_int]
        lib.proc_listchildpids.restype = ctypes.c_int
        size = 256
        while size <= 1 << 16:
            buf = (ctypes.c_int * size)()
            if lib.proc_listchildpids(pid, buf, ctypes.sizeof(buf)) < 0:
                return None
            found = []
            for value in buf:
                if value <= 0:
                    break
                found.append(int(value))
            if len(found) < size:
                return found
            size *= 4
        return found
    except Exception:  # noqa: BLE001 - no library, no symbol: the caller falls back
        return None


PS_WAIT = 10    # seconds the ps fallback is given: ps is slow on a heavily loaded host, and a tree that is not found is a program left running


def _below(kids, pid):
    """Every process below `pid` in `kids` ({parent: [children]}), a parent before its children."""
    found, seen, queue = [], {pid}, [pid]
    for parent in queue:
        for child in kids.get(parent, []):
            if child not in seen:
                seen.add(child)
                found.append(child)
                queue.append(child)
    return found


def _libproc_works(pid):
    """Whether an empty libproc answer for `pid` can be believed: libproc has just listed `pid` as this tool's own child, or, when `pid`
    is the tool itself, has just listed the tool as its parent's child. A library that lists nothing for a live process is not working
    (as in a sandbox that denies it)."""
    if pid in (_children_libproc(os.getpid()) or []):
        return True
    return pid == os.getpid() and os.getpid() in (_children_libproc(os.getppid()) or [])


def list_descendants(pid):
    """Every process below `pid` (never one beside it): from /proc where there is one, else from libproc, else from ps (given PS_WAIT
    seconds). libproc is believed when it lists a child; an empty answer is believed only when libproc has just listed this tool's own child
    `pid` (a library that answers nothing for a live child is not working, as in a sandbox that denies it), and otherwise ps is asked. The
    list carries .ident, the identity of each pid from the same reading. Raises TreeNotListed when the processes cannot be listed: that is
    never an empty list."""
    kids, ident = {}, {}
    try:
        if os.path.isdir("/proc/self"):
            started = time.monotonic()
            for entry in os.listdir("/proc"):
                if time.monotonic() - started > TABLE_SECONDS:
                    raise TreeNotListed("reading /proc took more than %d seconds" % TABLE_SECONDS)
                if entry.isdigit():
                    try:
                        with open("/proc/%s/stat" % entry, "rb") as fh:
                            fields = fh.read().rsplit(b")", 1)[1].split()
                        kids.setdefault(int(fields[1]), []).append(int(entry))
                        ident[int(entry)] = ("proc", int(fields[19]))
                    except (OSError, IndexError, ValueError):
                        continue
        else:
            first = _children_libproc(pid)
            if first:
                found, seen, stack = list(first), {pid, *first}, list(first)
                while stack:
                    for child in _children_libproc(stack.pop()) or []:
                        if child not in seen:
                            seen.add(child)
                            found.append(child)
                            stack.append(child)
                listing = _Listing(found)
                listing.ident = {}
                for child in found:
                    started = _libproc_start(child)
                    if started is not None:
                        listing.ident[child] = ("libproc", started)
                return listing
            if first is not None and _libproc_works(pid):
                listing = _Listing()
                listing.ident = {}
                return listing
            for row in _ps_rows("pid=,ppid=,lstart="):
                if len(row) >= 2 and row[0].isdigit() and row[1].isdigit():
                    kids.setdefault(int(row[1]), []).append(int(row[0]))
                    ident[int(row[0])] = ("ps", " ".join(row[2:])) if len(row) >= 6 else ("listed", None)
    except OSError as exc:
        raise TreeNotListed("the processes could not be read: %s" % type(exc).__name__) from exc
    listing = _Listing(_below(kids, pid))
    listing.ident = {child: ident[child] for child in listing if child in ident}
    return listing


def descendants(pid):
    """list_descendants for a caller that cannot take an exception (a signal handler): the same list, but when the tree cannot be listed the
    list is empty, has not_listed = True, and process_notes() says so."""
    try:
        return list_descendants(pid)
    except TreeNotListed as exc:
        _note("the processes below pid %d could not be listed (%s)" % (pid, exc))
        listing = _Listing()
        listing.ident = {}
        listing.not_listed = True
        return listing


def _process_table():
    """{pid: (parent pid, process group)} for every process, from /proc where there is one, else from ps (given PS_WAIT seconds); .ident holds
    each pid's identity from the same reading. Raises TreeNotListed when neither answers."""
    table, ident = _Table(), {}
    try:
        if os.path.isdir("/proc/self"):
            started = time.monotonic()
            for entry in os.listdir("/proc"):
                if time.monotonic() - started > TABLE_SECONDS:
                    raise TreeNotListed("reading /proc took more than %d seconds" % TABLE_SECONDS)
                if entry.isdigit():
                    try:
                        with open("/proc/%s/stat" % entry, "rb") as fh:
                            fields = fh.read().rsplit(b")", 1)[1].split()
                        table[int(entry)] = (int(fields[1]), int(fields[2]))
                        ident[int(entry)] = ("proc", int(fields[19]))
                    except (OSError, IndexError, ValueError):
                        continue
        else:
            for row in _ps_rows("pid=,ppid=,pgid=,lstart="):
                if len(row) >= 3 and all(part.isdigit() for part in row[:3]):
                    table[int(row[0])] = (int(row[1]), int(row[2]))
                    ident[int(row[0])] = ("ps", " ".join(row[3:])) if len(row) >= 8 else ("listed", None)
    except OSError as exc:
        raise TreeNotListed("the processes could not be read: %s" % type(exc).__name__) from exc
    table.ident = ident
    return table


def _sample(pid):
    """Remember what is below `pid` now, by the cheap routes only (/proc, or libproc on macOS; never a program): a process that is seen
    here and later loses its parent is the tool's to end, and one that was never seen is not."""
    try:
        if os.path.isdir("/proc/self"):
            table = _process_table()
            kids = {}
            for child, (parent, _group) in table.items():
                kids.setdefault(parent, []).append(child)
            _seen_below(_below(kids, pid), table.ident)
        else:
            seen, stack = {pid}, [pid]
            while stack:
                for child in _children_libproc(stack.pop()) or []:
                    if child not in seen:
                        seen.add(child)
                        stack.append(child)
            idents = {child: ("libproc", started) for child in seen - {pid} for started in [_libproc_start(child)] if started is not None}
            _seen_below(seen - {pid}, idents)
    except Exception:  # noqa: BLE001 - a sample is best effort
        pass


def _pipe_inodes(proc):
    """The inodes of the pipes the tool holds with `proc` (Linux: /proc names a pipe by it; elsewhere the answer is not used)."""
    found = set()
    for handle in (proc.stdin, proc.stdout, proc.stderr):
        try:
            if handle is not None:
                found.add(os.fstat(handle.fileno()).st_ino)
        except (OSError, ValueError):
            pass
    return found


def _holds_pipe(pid, inodes):
    """Whether `pid` holds one of the pipes (Linux only, from /proc/<pid>/fd): the pipes are private to the tool and what it started."""
    try:
        for name in os.listdir("/proc/%d/fd" % pid):
            try:
                link = os.readlink("/proc/%d/fd/%s" % (pid, name))
            except OSError:
                continue
            if link.startswith("pipe:[") and link.endswith("]") and int(link[6:-1]) in inodes:
                return True
    except (OSError, ValueError):
        pass
    return False


def reap_orphans(inodes=None):
    """Kill what this tool started and lost: a process of the tool's own group that is no longer below the tool (its parent ended and
    init adopted it, so the walk from a program's pid cannot find it) and that the tool knows to be its own: it was seen below the tool
    (SEEN: the programs it started, the trees it listed, the samples taken while it waited), or, on Linux, it holds one of `inodes`,
    the pipes the tool made. A process the tool never saw in its tree is not touched, whoever leads the group: the next stage of a
    pipeline the tool heads, or a process a launcher put in the group, is not the tool's. A process outside the group is never looked
    at, and a pid is checked against the group, and against the identity it had when it was seen (same_process), at the moment it is
    signalled. Returns the pids signalled; when the processes cannot be listed it signals none and process_notes() says so."""
    me = os.getpid()
    try:
        if os.getpgrp() != me:
            return []
    except OSError:
        return []
    try:
        table = _process_table()
    except TreeNotListed as exc:
        _note("what the tool started and lost could not be looked for: the processes could not be listed (%s)" % exc)
        return []
    kids = {}
    for pid, (parent, _group) in table.items():
        kids.setdefault(parent, []).append(pid)
    below = set(_below(kids, me))
    on_linux = os.path.isdir("/proc/self")
    killed = []
    started = time.monotonic()
    for pid, (_parent, group) in table.items():
        if time.monotonic() - started > TABLE_SECONDS:
            _note("the look for what the tool started and lost was cut after %d seconds" % TABLE_SECONDS)
            break
        if group != me or pid == me or pid in below:
            continue
        listed = table.ident.get(pid)
        holder = False
        if pid in SEEN:
            before = SEEN_IDENT.get(pid)
            if before is not None and listed is not None and before != listed:
                continue                           # the pid is another process's now: one the tool never saw
        elif inodes and on_linux and _holds_pipe(pid, inodes):
            holder = True
        else:
            continue
        try:
            if os.getpgid(pid) != me:
                continue
            if not same_process(pid, listed) or (holder and not _holds_pipe(pid, inodes)):
                continue
            os.kill(pid, signal.SIGKILL)
            killed.append(pid)
        except OSError:
            pass
    return killed


def _stop_below(root, stopped):
    """Stop (SIGSTOP) every process below `root` as the walk finds it, so one that forks fast cannot outrun the walk, and repeat the walk
    for what the stopped ones had already forked, for at most MAX_ROUNDS rounds and WALK_SECONDS seconds. `stopped` gets {pid: identity}.
    Returns None, or the sentence that says the tree could not be listed or that the walk was cut."""
    began = time.monotonic()
    for _round in range(MAX_ROUNDS):
        try:
            found = list_descendants(root)
        except TreeNotListed as exc:
            return _note("the processes below pid %d could not be listed (%s): the program itself was ended, nothing below it" % (root, exc))
        listed = getattr(found, "ident", None) or {}
        _seen_below(found, listed)
        fresh = [pid for pid in found if pid not in stopped]
        if not fresh:
            return None
        for pid in fresh:
            if not same_process(pid, listed.get(pid)):
                continue
            try:
                os.kill(pid, signal.SIGSTOP)
                stopped[pid] = listed.get(pid)
            except OSError:
                pass
        if time.monotonic() - began > WALK_SECONDS:
            break
    return _note("the walk below pid %d was cut at %d rounds or %d seconds: a process started after it may be running" % (root, MAX_ROUNDS, WALK_SECONDS))


def _end(stopped):
    """Kill the stopped set, each pid only if it is still the process that was stopped."""
    for pid, ident in list(stopped.items()):
        if same_process(pid, ident):
            try:
                os.kill(pid, signal.SIGKILL)
            except OSError:
                pass


def kill_tree(proc):
    """Kill the program and everything it started. The program is stopped first and then each process below it as the walk finds it
    (_stop_below), so the tree does not grow while it is listed; the stopped set is killed after the program. A pid is killed only if it
    is still the process that was listed (same_process). A program already waited for is not touched: its pid is free to be another
    process's, and the walk below it would be that process's children. Returns None, or a sentence when the tree could not be listed or
    the walk was cut."""
    if proc.poll() is not None:
        return None
    try:
        proc.send_signal(signal.SIGSTOP)    # a program that is stopped forks nothing more while its tree is listed
    except OSError:
        pass
    stopped, note = {}, None
    try:
        note = _stop_below(proc.pid, stopped)
    finally:
        try:
            proc.kill()
        except OSError:
            pass
        _end(stopped)
    return note


def _stat_row(pid):
    """(state letter, parent pid, identity) of `pid` from /proc/<pid>/stat, or None when it is gone or cannot be read. The identity is the one
    process_ident gives (field 22, counted after the last ")")."""
    try:
        with open("/proc/%d/stat" % pid, "rb") as fh:
            data = fh.read()
        rest = data[data.rindex(b")") + 2:].split()
        return rest[0].decode("ascii", "replace"), int(rest[1]), ("proc", int(rest[19]))
    except (OSError, ValueError, IndexError):
        return None


def _children_of_me():
    """{pid: (state, identity)} of the direct children of this process (Linux). The kernel's own list of each thread's children is read where
    there is one (no scan of every process), and every pid it names is checked against /proc/<pid>/stat; where there is none, /proc is
    scanned. Raises TreeNotListed when /proc cannot be read or takes more than TABLE_SECONDS."""
    me = os.getpid()
    pids = None
    try:
        named = set()
        for tid in os.listdir("/proc/%d/task" % me):
            with open("/proc/%d/task/%s/children" % (me, tid)) as fh:
                named.update(int(part) for part in fh.read().split())
        pids = sorted(named)
    except (OSError, ValueError):
        pids = None
    if pids is None:
        try:
            pids = [int(entry) for entry in os.listdir("/proc") if entry.isdigit()]
        except OSError as exc:
            raise TreeNotListed("the processes could not be read: %s" % type(exc).__name__) from exc
    found, started = {}, time.monotonic()
    for pid in pids:
        if time.monotonic() - started > TABLE_SECONDS:
            raise TreeNotListed("reading /proc took more than %d seconds" % TABLE_SECONDS)
        row = _stat_row(pid)
        if row is not None and row[1] == me:
            found[pid] = (row[0], row[2])
    return found


def _unproven(text):
    """Record why this block cannot say that no program left a process behind (once, at most 20) and return it."""
    if text not in LEFT["unproven"] and len(LEFT["unproven"]) < 20:
        LEFT["unproven"].append(text)
    return text


def become_subreaper():
    """On Linux ask the kernel to make this process the parent of every process a program leaves behind (PR_SET_CHILD_SUBREAPER = 36), so that
    one that left the tool's group or session, or holds none of its descriptors, is a child of the tool and settle() can find it. Called by
    spawn() before the first program; once. PRE_KIDS records the children the tool already had (pid and start time): they are not a program's
    and settle() leaves them. Where the kernel refuses, or the host is not Linux, nothing is adopted: settle() falls back to what the tool
    saw below a program (SEEN), and the answer cannot prove that nothing was left (process_verdict()['unproven']). Returns whether it is on."""
    if SUB["tried"]:
        return SUB["on"]
    SUB["tried"] = True
    if sys.platform.startswith("linux") and ctypes is not None:
        try:
            SUB["on"] = ctypes.CDLL(None, use_errno=True).prctl(36, 1, 0, 0, 0) == 0
        except Exception:  # noqa: BLE001 - no libc symbol, a sandbox: the caller falls back
            SUB["on"] = False
        if SUB["on"]:
            try:
                PRE_KIDS.update({pid: ident for pid, (_state, ident) in _children_of_me().items()})
            except TreeNotListed as exc:
                _unproven(_note("the children the tool already had could not be listed (%s): one of them may be taken for a program's" % exc))
        else:
            _unproven("this host refused PR_SET_CHILD_SUBREAPER: a process a program left behind outside the walk is not adopted and may not be found")
    else:
        reason = "this host cannot adopt orphaned processes (no PR_SET_CHILD_SUBREAPER): a process a program left behind may not be found"
        SUB["note"] = reason              # in process_verdict()["notes"], never in process_notes(): a tool that reads only what a program printed is not made partial by it
        if NONLINUX_UNPROVEN_DOWNGRADE:
            _unproven(reason)
    return SUB["on"]


def process_keep(pid):
    """Let `pid` stay: settle() does not end it. For a process a program leaves on purpose (a daemon the tool stops itself); spawn(argv,
    leaves=True) does it for what that program leaves. A kept process is still ended by a stop signal (kill_all)."""
    ident = process_ident(pid)
    if ident is not None:
        KEEP[pid] = ident


def _exempt(pid, ident, active):
    """Whether the process `pid` (identity `ident`) is the tool's own and not a program's leftover: a program spawn() started (Popen owns it
    and reaps it), one in ACTIVE (`active`, their pids), one kept (KEEP) or one the tool already had (PRE_KIDS). A pid whose identity differs is
    another process that has the number now."""
    if pid in active:
        return True
    for table in (SPAWNED, KEEP, PRE_KIDS):
        if pid in table and (table[pid] is None or table[pid] == ident):
            return True
    return False


def _victims_children(active):
    """[(pid, state, identity)]: the children of this tool that are no program's own (Linux, with the subreaper on)."""
    return [(pid, state, ident) for pid, (state, ident) in sorted(_children_of_me().items()) if not _exempt(pid, ident, active)]


def _victims_seen(active):
    """[(pid, state, identity)]: where nothing is adopted, the processes that were seen below a program, are still the ones that were seen, and
    have lost their parent (the parent is not the tool and is not a live process the tool saw). Raises TreeNotListed."""
    me = os.getpid()
    candidates = [pid for pid in list(SEEN) if pid != me and SEEN_IDENT.get(pid) is not None and not _exempt(pid, SEEN_IDENT[pid], active)]
    if not candidates:
        return []
    table = _process_table()
    found = []
    for pid in candidates:
        row, listed = table.get(pid), table.ident.get(pid)
        if row is None or listed != SEEN_IDENT[pid] or row[0] == me:
            continue
        parent = row[0]
        if parent in table and SEEN_IDENT.get(parent) is not None and table.ident.get(parent) == SEEN_IDENT[parent]:
            continue                               # its parent is a live process of a program's tree: the program has not ended
        found.append((pid, "S", listed))
    return found


def _stop_under(roots, stopped, deadline):
    """_stop_below for several roots at once with one reading of the processes per round (a program may leave thousands): stop (SIGSTOP)
    every process below any of `roots` as the walk finds it, for at most MAX_ROUNDS rounds, WALK_SECONDS seconds and until `deadline`.
    `stopped` gets {pid: identity}. Returns None, or the sentence that says the tree could not be listed or that the walk was cut."""
    began = time.monotonic()
    for _round in range(MAX_ROUNDS):
        try:
            table = _process_table()
        except TreeNotListed as exc:
            return _unproven(_note("the processes below what a program left behind could not be listed (%s): the leftovers were ended, nothing below them" % exc))
        kids = {}
        for child, (parent, _group) in table.items():
            kids.setdefault(parent, []).append(child)
        fresh = []
        for root in roots:
            fresh.extend(pid for pid in _below(kids, root) if pid not in stopped)
        if not fresh:
            return None
        for pid in fresh:
            ident = table.ident.get(pid)
            if pid not in stopped and same_process(pid, ident):
                try:
                    os.kill(pid, signal.SIGSTOP)
                    stopped[pid] = ident
                except OSError:
                    pass
        if time.monotonic() > min(deadline, began + WALK_SECONDS):
            break
    return _unproven(_note("the walk below what a program left behind was cut at %d rounds or %d seconds: a process started after it may be running" % (MAX_ROUNDS, WALK_SECONDS)))


def _end_counting(stopped):
    """Kill the stopped set, each pid only if it is still the process that was stopped. How many were alive (a zombie was not left running)."""
    alive = 0
    for pid, ident in list(stopped.items()):
        row = _stat_row(pid)
        if not same_process(pid, ident):
            continue
        try:
            os.kill(pid, signal.SIGKILL)
            if row is None or row[0] not in ("Z", "X"):
                alive += 1
        except OSError:
            pass
    return alive


def _end_children(victims, deadline):
    """End the leftovers that are this tool's children: each is stopped (its identity and parent read again first), what it started is stopped
    with it (_stop_under), the set is killed, and the children are reaped (waitpid WNOHANG: the tool is their parent). The clock is read for
    every one, so a program that left thousands is cut at `deadline`, not after a pass. Returns how many live processes were killed."""
    me = os.getpid()
    stopped, reap, cut = {}, [], False
    try:
        for pid, _state, ident in victims:
            if time.monotonic() >= deadline:
                cut = True
                break
            row = _stat_row(pid)
            if row is None or row[1] != me or row[2] != ident:
                continue                           # gone, or not this tool's child any more
            if row[0] in ("Z", "X"):
                reap.append(pid)
                continue
            try:
                os.kill(pid, signal.SIGSTOP)
            except OSError:
                continue
            stopped[pid] = ident
            reap.append(pid)
        _stop_under(list(stopped), stopped, deadline)
    finally:
        alive = _end_counting(stopped)
    pending = set(reap)
    while pending:
        for pid in list(pending):
            try:
                done, _status = os.waitpid(pid, os.WNOHANG)
            except OSError:
                pending.discard(pid)               # not this tool's child (any more): nothing to reap
                continue
            if done:
                pending.discard(pid)
        if not pending:
            break
        if time.monotonic() >= deadline:
            _unproven(_note("%d processes a program left behind did not end within %d seconds" % (len(pending), LEFTOVER_SECONDS)))
            break
        time.sleep(0.005)
    if cut:
        _unproven(_note("a program left more processes than could be ended within %d seconds: some are still running" % LEFTOVER_SECONDS))
    return alive


def _end_seen(victims, deadline):
    """End the leftovers where nothing is adopted: stopped, what they started stopped with them, then killed (each only if it is still the
    process that was seen). Returns how many live processes were killed."""
    stopped = {}
    try:
        for pid, _state, ident in victims:
            if time.monotonic() >= deadline:
                _unproven(_note("a program left more processes than could be ended within %d seconds: some are still running" % LEFTOVER_SECONDS))
                break
            if same_process(pid, ident):
                try:
                    os.kill(pid, signal.SIGSTOP)
                    stopped[pid] = ident
                except OSError:
                    pass
        _stop_under(list(stopped), stopped, deadline)
    finally:
        alive = _end_counting(stopped)
    return alive


def _settle(final):
    active = {proc.pid for proc in list(ACTIVE)}
    if not final and any(proc.poll() is None for proc in list(ACTIVE)):
        _unproven(_note("a program was still running when another one ended: what is left behind cannot be told from what that program started, so nothing was ended"))
        return 0
    deadline = time.monotonic() + LEFTOVER_SECONDS
    victims = _victims_children if SUB["on"] else _victims_seen
    ended, looked = 0, False
    ready = [proc for proc in list(LEAVES.values()) if proc.poll() is not None]
    if ready:
        for proc in ready:                         # a program that leaves a process on purpose: what it left stays
            LEAVES.pop(proc.pid, None)
        for pid, state, ident in victims(active):
            if state not in ("Z", "X"):
                KEEP[pid] = ident
    while True:
        found = victims(active)
        if not found:
            if ended and not looked:
                looked = True                      # one more look after a short pause: a fork that was under way when the first one died
                time.sleep(SETTLE_LOOK)
                continue
            return ended
        if time.monotonic() >= deadline:
            _unproven(_note("%d processes a program left behind were still there after %d seconds: they were not all ended" % (len(found), LEFTOVER_SECONDS)))
            return ended
        ended += (_end_children if SUB["on"] else _end_seen)(found, deadline)
        if not SUB["on"]:
            return ended                           # nothing is adopted: one pass, the processes are not this tool's to reap


def settle(final=False):
    """Look for what the programs this tool ran have left behind, and end it: the processes that are the tool's children and no program's own
    (the subreaper adopted them) are stopped, what they started with them, killed and reaped, for at most LEFTOVER_SECONDS (the clock is read for
    every process, and one more look follows an ending). Never a process of another program: while another program is running in ACTIVE nothing
    is ended and process_verdict() says it is unproven. Never a program spawn() started (Popen owns its exit status: its returncode is never
    taken), nor KEEP, PRE_KIDS or a process outside the tool's own children. final=True is the stop signal's own call (kill_all). Runs on the
    caller's thread, joins none and never raises. Returns how many live processes it ended; process_verdict() holds the totals."""
    if SETTLING[0] and not final:
        return 0
    SETTLING[0] = True
    try:
        ended = _settle(final)
        LEFT["left_behind"] += ended
        return ended
    except Exception as exc:  # noqa: BLE001 - never into the finally of a carrier: say it could not be proven
        _unproven(_note("the look for what a program left behind failed (%s)" % type(exc).__name__))
        return 0
    finally:
        SETTLING[0] = False


def process_verdict():
    """What an answer says about the programs the tool ran: {"subreaper": whether orphans were adopted, "left_behind": how many live processes
    settle() ended, "unproven": why 'nothing was left behind' cannot be claimed (empty when it can), "notes": process_notes()}."""
    return {"subreaper": SUB["on"], "left_behind": LEFT["left_behind"], "unproven": list(LEFT["unproven"]), "notes": process_notes() + ([SUB["note"]] if SUB["note"] else [])}


def process_apply(answer):
    """Put process_verdict() into `answer` as answer["program_group"] and, when a program left a process behind or that cannot be ruled out,
    turn a complete answer into a partial one (status "partial", the ok and complete flags that are there false, a sentence in status_basis;
    a call of communicate_bounded that was cut at POST_EXIT_BYTES counts, PIPE_CUT):
    what a program wrote while the tool read it is not a complete result. A carrier calls it once where it prints its answer. Returns `answer`."""
    verdict = process_verdict()
    answer["program_group"] = verdict
    if (verdict["left_behind"] > 0 or verdict["unproven"] or PIPE_CUT["cut"]) and answer.get("status") == "complete":
        answer["status"] = "partial"
        for flag in ("ok", "complete"):
            if flag in answer:
                answer[flag] = False
        if verdict["left_behind"] > 0:
            sentence = "a program left %d process%s running after it ended; the tool ended them, and what they wrote before that is in the files named here" % (
                verdict["left_behind"], "" if verdict["left_behind"] == 1 else "es")
        elif PIPE_CUT["cut"]:
            sentence = "a process that held a program's pipe after it ended went on writing; the tool read no more than %d bytes of it and let the pipe go" % POST_EXIT_BYTES
        else:
            sentence = "the tool cannot prove that no program left a process behind (see program_group.unproven)"
        basis = answer.get("status_basis")
        answer["status_basis"] = "%s; %s" % (basis, sentence) if isinstance(basis, str) and basis else sentence
    return answer


PIPE_GRACE = 1.0    # seconds the pipes of a program that has ended are given to reach end of file
POST_EXIT_BYTES = 1 << 20    # the most bytes (both pipes together) read from the pipes of a program that has ended
PIPE_CUT = {"cut": 0}        # how many calls stopped reading at POST_EXIT_BYTES because a process still held the pipes and went on writing


def communicate_bounded(proc, seconds, input=None):
    """(stdout bytes, stderr bytes, timed out) for a program started with pipes, in bytes. At `seconds` the program and what it started
    are killed (timed out). A program that has ended while something it started still holds its pipes (a daemon, a helper that
    inherited them) does not hold the tool: from the moment the program has ended (or was killed) the pipes are given PIPE_GRACE seconds
    and POST_EXIT_BYTES bytes, whichever is used up first; what the program wrote is kept, what the tool lost is killed (reap_orphans,
    settle), and the pipes are let go. A cut at the byte cap is counted in PIPE_CUT and noted (process_notes()); the return shape is the
    same. The pipes are read here and by nothing else (not by Popen.communicate), so letting them go is safe. `input` is written while
    the program runs and is dropped once it has ended."""
    deadline = time.monotonic() + max(0.1, seconds)
    bufs = (bytearray(), bytearray())
    sel = _selectors.DefaultSelector()
    pending = memoryview(input) if input and proc.stdin is not None else None
    for index, stream in enumerate((proc.stdout, proc.stderr)):
        if stream is not None:
            sel.register(stream, _selectors.EVENT_READ, index)
    if proc.stdin is not None:
        if pending:
            sel.register(proc.stdin, _selectors.EVENT_WRITE, 2)
        else:
            _close_pipe(proc.stdin)
    timed_out, note, ended, extra, cut, sampled = False, None, None, 0, False, 0.0
    try:
        while True:
            now = time.monotonic()
            if ended is None:
                if proc.poll() is not None:
                    ended = now
                elif now >= deadline:
                    timed_out = True
                    note = kill_tree(proc)
                    ended = time.monotonic()
                elif now - sampled >= 0.2:
                    sampled = now
                    _sample(proc.pid)
            if ended is not None:
                if pending is not None:
                    sel.unregister(proc.stdin)
                    _close_pipe(proc.stdin)
                    pending = None
                if not any(key.data != 2 for key in sel.get_map().values()) or extra >= POST_EXIT_BYTES or now - ended >= PIPE_GRACE:
                    cut = extra >= POST_EXIT_BYTES and any(key.data != 2 for key in sel.get_map().values())
                    break
            wait = max(0.01, min(0.2, (deadline if ended is None else ended + PIPE_GRACE) - now))
            if not sel.get_map():
                try:
                    proc.wait(timeout=wait)
                except subprocess.TimeoutExpired:
                    pass
                continue
            for key, _mask in sel.select(wait):
                if key.data == 2:
                    try:
                        pending = pending[os.write(key.fd, pending[:_select.PIPE_BUF]):]
                    except OSError:
                        pending = None
                    if not pending:
                        sel.unregister(proc.stdin)
                        _close_pipe(proc.stdin)
                        pending = None
                    continue
                if ended is not None and extra >= POST_EXIT_BYTES:
                    break
                try:
                    data = os.read(key.fd, 65536 if ended is None else min(65536, POST_EXIT_BYTES - extra))
                except OSError:
                    data = b""
                if not data:
                    sel.unregister(key.fileobj)
                    continue
                bufs[key.data].extend(data)
                if ended is not None:
                    extra += len(data)
        if any(key.data != 2 for key in sel.get_map().values()):
            reap_orphans(_pipe_inodes(proc))
            settle()
    finally:
        sel.close()
        for pipe in (proc.stdin, proc.stdout, proc.stderr):
            _close_pipe(pipe)
    if cut:
        PIPE_CUT["cut"] += 1
        _note("a process that held a program's pipe after the program ended went on writing: the tool read %d bytes more and let the pipe go" % POST_EXIT_BYTES)
    try:
        proc.wait(timeout=PIPE_GRACE)
    except subprocess.TimeoutExpired:
        pass
    settle()
    err = bytes(bufs[1])
    if note:
        err = err + (b"\n" if err else b"") + note.encode("utf-8", "replace")
    return bytes(bufs[0]), err, timed_out


def _close_pipe(pipe):
    try:
        if pipe is not None:
            pipe.close()
    except (OSError, ValueError):
        pass


def kill_all():
    """End every program the tool has running, with what each started. Then everything below the tool itself, which is the tool's own: a
    program forked a moment before it was entered in ACTIVE is among it. Then what an earlier program started and lost (reap_orphans).
    Returns the sentences for what could not be done (also in process_notes())."""
    notes = []
    for proc in list(ACTIVE):
        note = kill_tree(proc)
        if note:
            notes.append(note)
    stopped = {}
    try:
        note = _stop_below(os.getpid(), stopped)
        if note:
            notes.append(note)
    finally:
        _end(stopped)
    reap_orphans()
    settle(True)     # what the stop ended below the tool is reaped (bounded; settle never raises)
    return notes


def _on_signal(signum, _frame):
    for other in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(other, signal.SIG_IGN)     # the first signal counts: a second one starts no second answer
    kill_all()
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
        out, err, timed_out = communicate_bounded(proc, max(1.0, seconds))
        return (None if timed_out else proc.returncode), out, err, timed_out
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


# --- heic_inspect ---------------------------------------------------------------------------------------------------------

DEFAULT_MAX_SECONDS = 240
MAX_SECONDS_CAP = 255       # manifest.json timeout_seconds (300) less the work after the stages and the time to write the answer
DEFAULT_LIMIT = 200
INLINE_BYTES = 1 << 20
DEFAULT_MAX_PIXELS = 200000000      # the pixels the original's own ispe may declare before a conversion is refused
MAX_PIXELS_CAP = 4000000000
DEFAULT_MAX_BYTES = 1 << 30         # the size of the original past which a conversion is refused
MAX_BYTES_CAP = 1 << 40
MAX_BOXES = 20000
MAX_ENTRIES = 100000               # entries read from one iinf, iloc, ipma, ipco or iref
BODY_CAP = 8 << 20                 # the most of one box body that is read
MAX_PROBLEMS_INLINE = 100
MAX_PREVIEW_BYTES = 1 << 30        # the output directory's cap while the backend runs
MAX_LOG_BYTES = 16 << 20           # the output of the backend and of exiftool, each, kept in a work file
MAX_WORK_FILES = 1000
FLOOD_STEP = 0.1
BRANDS = ("heic", "heix", "mif1", "msf1")
IMAGE_TYPES = ("hvc1", "hev1", "av01", "avc1", "jpeg", "j2k1", "grid", "iovl", "unci", "vvc1")
FORMATS = ("jpeg", "png")
BACKENDS = ("heif-convert", "pillow-heif")
ARGUMENTS = ("path", "format", "quality", "image", "backend", "convert", "write_values", "max_pixels", "max_bytes", "max_output_bytes", "max_seconds", "limit")
HEIF_CONVERT_STAGE = 0.45         # shares of max_seconds: the exiftool run, then the backend, then the rest for the answer
EXIFTOOL_STAGE = 0.2
COPY_CHUNK = 1 << 20
KNOWN_GROUPS = ("EXIF", "IFD0", "IFD1", "ExifIFD", "InteropIFD", "GPS", "XMP", "ICC_Profile", "MakerNotes", "File", "ExifTool", "Composite", "QuickTime", "Meta", "Apple", "HEIC", "Track1", "ItemList", "Keys", "System")


class OutOfTime(Exception):
    pass


class NotRegular(Exception):
    pass


def fd_flags(extra=0):
    return os.O_RDONLY | extra | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)


def open_regular(path):
    """(fd, fstat) of a regular file, opened without waiting and without following a link: a FIFO, a device or a link at the name is
    never read (a FIFO would hold the tool for ever)."""
    fd = os.open(path, fd_flags())
    try:
        info = os.fstat(fd)
    except OSError:
        os.close(fd)
        raise
    if not stat.S_ISREG(info.st_mode):
        os.close(fd)
        raise NotRegular(stat.S_IFMT(info.st_mode))
    return fd, info


def output_base():
    job, out = os.environ.get("JOB_ID"), os.environ.get("OUT")
    if job and out:
        return Path(out), "store/jobs/%s/out" % safe_name(job)
    base = Path("work") / safe_name(os.environ.get("AGENT_ID") or "tool")
    return base, str(base)


class ResultFile:
    """One line per box and per problem, written as it is known and flushed at once, so that the count the answer gives is the lines the
    file holds, whatever ends the run. The inline page is a prefix. The file takes its name without replacing an earlier one (PLACE); the
    hidden temporary is registered for removal before it exists and is removed by a failure and by a stop."""

    def __init__(self, base, shown_base, key, limit, byte_limit):
        self.limit, self.byte_limit = limit, byte_limit
        self.page, self.page_bytes, self.rows, self.bytes_bound_hit = [], 0, 0, False
        digest = hashlib.sha256(dumps([key, NONCE], sort_keys=True).encode("utf-8")).hexdigest()[:16]
        name = "%s-boxes-%s.jsonl" % (TOOL, digest)
        self.dir = base / "tool-output"
        self.target = self.dir / name
        self.shown_dir = shown_base + "/tool-output/"
        self.shown = self.shown_dir + name
        self._out = None
        self._tmp = None
        self._cleanup = None
        OPEN_PAGES.append(self)

    def open(self):
        if self._out is not None:
            return
        self.dir.mkdir(parents=True, exist_ok=True)
        fd, name = tempfile.mkstemp(dir=str(self.dir), prefix=".%s-" % TOOL)
        self._tmp = Path(name)
        tmp = self._tmp
        self._cleanup = lambda: tmp.unlink() if tmp.exists() or tmp.is_symlink() else None
        CLEANUP.append(self._cleanup)
        self._out = os.fdopen(fd, "w", encoding="utf-8")

    def add(self, row):
        self.open()
        text = dumps(row)
        self._out.write(text)
        self._out.write("\n")
        self._out.flush()
        self.rows += 1
        if len(self.page) < self.limit and self.page_bytes + len(text) <= self.byte_limit:
            self.page.append(row)
            self.page_bytes += len(text)
        elif len(self.page) < self.limit:
            self.bytes_bound_hit = True

    def finish(self):
        self.open()
        out, self._out = self._out, None
        out.flush()
        os.fsync(out.fileno())
        out.close()
        placed = place_without_replacing(self._tmp, self.target)
        if self._cleanup in CLEANUP:
            CLEANUP.remove(self._cleanup)
        result = {"rows": self.rows, "returned": len(self.page), "truncated": self.rows > len(self.page),
                  "inline_byte_limit": self.byte_limit, "all_results": self.shown_dir + placed.name,
                  "all_results_format": "JSON Lines, one box or one problem of the original per line"}
        if self.bytes_bound_hit:
            result["inline_bounded_by_bytes"] = True
        if placed != self.target:
            result["earlier_result_kept"] = self.shown
        return result


def refuse_linked_dir(path, what):
    """A directory this tool writes into is never reached through a link planted in the output directory: lstat, not stat."""
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        return
    except OSError as exc:
        fail("%s could not be examined: %s" % (what, describe(exc)))
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        fail("%s in the output directory is a symbolic link or not a directory: the tool does not write through it" % what, written=False)


def choose_values_name(out):
    global VALUES_NAME
    stem = "heic-inspect-values"
    for n in range(1, 1000):
        name = "%s%s.jsonl" % (stem, "" if n == 1 else "-%d" % n)
        if not os.path.lexists(os.path.join(out, name)):
            VALUES_NAME = name
            return
    fail("no free name for the values file in the output directory")


def fourcc(raw):
    return "".join(chr(b) if 32 <= b < 127 else "\\x%02x" % b for b in raw)


def cstr(raw):
    end = raw.find(b"\0")
    return raw if end < 0 else raw[:end]


# --- the box walk ---------------------------------------------------------------------------------------------------------------

class Reader:
    def __init__(self, fd, size, deadline):
        self.fd, self.size, self.deadline = fd, size, deadline

    def read(self, offset, length):
        if length <= 0 or offset < 0 or offset >= self.size:
            return b""
        if time.monotonic() > self.deadline:
            raise OutOfTime()
        return os.pread(self.fd, min(length, self.size - offset), offset)


class Walk:
    """The boxes of an ISO-BMFF file that a HEIF reader needs, read with the standard library: every length is checked against its parent and
    the file before it is used, every count against what the box can hold, and what is wrong is a problem (with its offset) and not a stop,
    where the walk can go on."""

    def __init__(self, reader, rows):
        self.rd = reader
        self.rows = rows               # a callable: row -> None (the result file)
        self.boxes = 0
        self.truncated = False
        self.problem_count = 0
        self.problems = []
        self.not_entered = 0
        self.brands = None
        self.handler = None
        self.primary = None
        self.items = {}                # item_ID -> {"type", "hidden", "name"}
        self.item_order = []
        self.declared_items = None
        self.props = []                # ipco children in order: (type, info)
        self.assoc = {}                # item_ID -> [property indexes]
        self.locations = {}            # item_ID -> {"method", "extents": [(offset, length)], "base"}
        self.refs = {}                 # reference type -> {from_ID: [to_IDs]}
        self.meta_seen = False
        self.top = []

    def problem(self, offset, kind, text):
        self.problem_count += 1
        row = {"problem": kind, "offset": offset, "note": text}
        if len(self.problems) < MAX_PROBLEMS_INLINE:
            self.problems.append(row)
        self.rows(row)

    def boxes_in(self, start, end, depth, path):
        """(offset, size, header length, type) of the boxes of [start, end), in order."""
        off = start
        while off < end:
            if self.boxes >= MAX_BOXES:
                if not self.truncated:
                    self.problem(off, "walk_truncated", "the walk stopped at %d boxes: the boxes from this offset on are not read" % MAX_BOXES)
                self.truncated = True
                return
            head = self.rd.read(off, 16)
            if end - off < 8 or len(head) < 8:
                self.problem(off, "trailing_bytes", "%d byte(s) after the last box, too few for a box header" % (end - off))
                return
            size32, typ = struct.unpack(">I4s", head[:8])
            hdr = 8
            if size32 == 1:
                if end - off < 16 or len(head) < 16:
                    self.problem(off, "short_header", "a box with a 64-bit size and fewer than 16 bytes left")
                    return
                size = struct.unpack(">Q", head[8:16])[0]
                hdr = 16
            elif size32 == 0:
                size = end - off
            else:
                size = size32
            if typ == b"uuid":
                hdr += 16
            note = None
            if size < hdr:
                self.problem(off, "size_below_header", "box %s declares %d bytes, less than its own %d-byte header: the walk of this level stops" % (fourcc(typ), size, hdr))
                return
            if off + size > end:
                self.problem(off, "size_past_parent", "box %s declares %d bytes and %d remain in its parent (clipped)" % (fourcc(typ), size, end - off))
                note = "clipped from %d" % size
                size = end - off
            self.boxes += 1
            row = {"box": fourcc(typ), "offset": off, "size": size, "header": hdr, "depth": depth, "path": path}
            if size32 == 0:
                row["note"] = "size 0: runs to the end of its parent"
            if note:
                row["clipped"] = note
            self.rows(row)
            yield off, size, hdr, typ
            off += size

    def body(self, off, size, hdr, cap=BODY_CAP):
        return self.rd.read(off + hdr, min(size - hdr, cap))

    def top_level(self):
        for off, size, hdr, typ in self.boxes_in(0, self.rd.size, 0, ""):
            self.top.append(fourcc(typ))
            if typ == b"ftyp" and self.brands is None:
                data = self.body(off, size, hdr, 4096)
                if len(data) >= 8:
                    major, minor = data[:4], struct.unpack(">I", data[4:8])[0]
                    compat = [fourcc(data[i:i + 4]) for i in range(8, min(len(data) - len(data) % 4, 8 + 4 * 64), 4)]
                    self.brands = {"major": fourcc(major), "minor_version": minor, "compatible": compat}
                else:
                    self.problem(off, "ftyp_short", "ftyp holds fewer than 8 bytes")
            elif typ == b"meta":
                if self.meta_seen:
                    self.problem(off, "second_meta", "a second top-level meta box: the first one is read, this one is not")
                    self.not_entered += 1
                else:
                    self.meta_seen = True
                    self.meta(off, size, hdr)

    def fullbox(self, off, size, hdr):
        data = self.rd.read(off + hdr, 4)
        if len(data) < 4 or size - hdr < 4:
            self.problem(off, "fullbox_short", "a FullBox with no version and flags")
            return None
        return data[0], int.from_bytes(data[1:4], "big")

    def meta(self, off, size, hdr):
        head = self.fullbox(off, size, hdr)
        if head is None:
            return
        for coff, csize, chdr, ctyp in self.boxes_in(off + hdr + 4, off + size, 1, "meta"):
            if ctyp == b"hdlr":
                data = self.body(coff, csize, chdr, 64)
                if len(data) >= 12:
                    self.handler = fourcc(data[8:12])
            elif ctyp == b"pitm":
                self.pitm(coff, csize, chdr)
            elif ctyp == b"iinf":
                self.iinf(coff, csize, chdr)
            elif ctyp == b"iloc":
                self.iloc(coff, csize, chdr)
            elif ctyp == b"iprp":
                self.iprp(coff, csize, chdr)
            elif ctyp == b"iref":
                self.iref(coff, csize, chdr)
            elif ctyp in (b"meta",):
                self.not_entered += 1

    def pitm(self, off, size, hdr):
        head = self.fullbox(off, size, hdr)
        if head is None:
            return
        data = self.rd.read(off + hdr + 4, 4)
        if head[0] == 0 and len(data) >= 2:
            self.primary = struct.unpack(">H", data[:2])[0]
        elif head[0] >= 1 and len(data) >= 4:
            self.primary = struct.unpack(">I", data[:4])[0]
        else:
            self.problem(off, "pitm_short", "pitm is too short for its version")

    def iinf(self, off, size, hdr):
        head = self.fullbox(off, size, hdr)
        if head is None:
            return
        wide = head[0] != 0
        count_len = 4 if wide else 2
        data = self.rd.read(off + hdr + 4, count_len)
        if len(data) < count_len:
            self.problem(off, "iinf_short", "iinf has no entry count")
            return
        self.declared_items = int.from_bytes(data, "big")
        room = (size - hdr - 4 - count_len) // 12      # an infe is at least 12 bytes (a box header and a FullBox header and the fields)
        if self.declared_items > room:
            self.problem(off, "count_beyond_box", "iinf declares %d entries and its bytes hold at most %d: the count is not believed" % (self.declared_items, max(room, 0)))
        for coff, csize, chdr, ctyp in self.boxes_in(off + hdr + 4 + count_len, off + size, 2, "meta/iinf"):
            if ctyp != b"infe" or len(self.items) >= MAX_ENTRIES:
                continue
            head2 = self.fullbox(coff, csize, chdr)
            if head2 is None:
                continue
            raw = self.body(coff, csize, chdr, 600)[4:]
            version, flags = head2
            if version in (2, 3):
                idlen = 2 if version == 2 else 4
                if len(raw) < idlen + 2 + 4:
                    self.problem(coff, "infe_short", "infe is too short for its version")
                    continue
                item_id = int.from_bytes(raw[:idlen], "big")
                item_type = fourcc(raw[idlen + 2:idlen + 6])
                name = cstr(raw[idlen + 6:idlen + 6 + 256]).decode("utf-8", "replace")
            else:
                if len(raw) < 4:
                    self.problem(coff, "infe_short", "infe is too short for its version")
                    continue
                item_id, item_type, name = int.from_bytes(raw[:2], "big"), None, cstr(raw[4:4 + 256]).decode("utf-8", "replace")
            if item_id in self.items:
                self.problem(coff, "duplicate_item_id", "item %d is declared twice: the first is kept" % item_id)
                continue
            self.items[item_id] = {"type": item_type, "hidden": bool(flags & 1), "name_bytes": len(name.encode("utf-8"))}
            self.item_order.append(item_id)

    def iloc(self, off, size, hdr):
        head = self.fullbox(off, size, hdr)
        if head is None:
            return
        version = head[0]
        data = self.body(off, size, hdr)
        if len(data) < 8:
            self.problem(off, "iloc_short", "iloc is too short for its header")
            return
        offset_size, length_size = data[4] >> 4, data[4] & 15
        base_size = data[5] >> 4
        index_size = (data[5] & 15) if version in (1, 2) else 0
        pos = 6
        count_len = 4 if version == 2 else 2
        count = int.from_bytes(data[pos:pos + count_len], "big")
        pos += count_len
        if any(n not in (0, 4, 8) for n in (offset_size, length_size, base_size)) or index_size not in (0, 4, 8):
            self.problem(off, "iloc_sizes", "iloc field sizes %d/%d/%d/%d are not 0, 4 or 8" % (offset_size, length_size, base_size, index_size))
            return
        item_id_len = 4 if version == 2 else 2
        minimum = item_id_len + (2 if version in (1, 2) else 0) + 2 + base_size + 2
        if count > max((len(data) - pos) // max(minimum, 1), 0):
            self.problem(off, "count_beyond_box", "iloc declares %d items and its bytes hold at most %d: the count is not believed" % (count, (len(data) - pos) // max(minimum, 1)))
        for _ in range(min(count, MAX_ENTRIES)):
            if pos + item_id_len > len(data):
                break
            item_id = int.from_bytes(data[pos:pos + item_id_len], "big")
            pos += item_id_len
            method = 0
            if version in (1, 2):
                if pos + 2 > len(data):
                    break
                method = int.from_bytes(data[pos:pos + 2], "big") & 15
                pos += 2
            if pos + 2 + base_size + 2 > len(data):
                break
            pos += 2       # data_reference_index
            base = int.from_bytes(data[pos:pos + base_size], "big") if base_size else 0
            pos += base_size
            extent_count = int.from_bytes(data[pos:pos + 2], "big")
            pos += 2
            per = index_size + offset_size + length_size
            if per and extent_count > (len(data) - pos) // per:
                self.problem(off, "count_beyond_box", "item %d declares %d extents and the box holds at most %d" % (item_id, extent_count, (len(data) - pos) // per))
                extent_count = (len(data) - pos) // per
            extents = []
            for _e in range(min(extent_count, MAX_ENTRIES)):
                pos += index_size
                eoff = int.from_bytes(data[pos:pos + offset_size], "big") if offset_size else 0
                pos += offset_size
                elen = int.from_bytes(data[pos:pos + length_size], "big") if length_size else 0
                pos += length_size
                extents.append((eoff, elen))
            self.locations.setdefault(item_id, {"method": method, "base": base, "extents": extents})

    def iprp(self, off, size, hdr):
        for coff, csize, chdr, ctyp in self.boxes_in(off + hdr, off + size, 2, "meta/iprp"):
            if ctyp == b"ipco":
                for poff, psize, phdr, ptyp in self.boxes_in(coff + chdr, coff + csize, 3, "meta/iprp/ipco"):
                    if len(self.props) >= MAX_ENTRIES:
                        continue
                    info = {}
                    if ptyp == b"ispe":
                        data = self.body(poff, psize, phdr, 12)
                        if len(data) >= 12:
                            info = {"width": struct.unpack(">I", data[4:8])[0], "height": struct.unpack(">I", data[8:12])[0]}
                        else:
                            self.problem(poff, "ispe_short", "ispe is too short")
                    elif ptyp == b"irot":
                        data = self.body(poff, psize, phdr, 1)
                        if data:
                            info = {"angle": (data[0] & 3) * 90}
                    self.props.append((fourcc(ptyp), info))
            elif ctyp == b"ipma":
                self.ipma(coff, csize, chdr)

    def ipma(self, off, size, hdr):
        head = self.fullbox(off, size, hdr)
        if head is None:
            return
        version, flags = head
        data = self.body(off, size, hdr)
        if len(data) < 8:
            self.problem(off, "ipma_short", "ipma is too short for its header")
            return
        count = struct.unpack(">I", data[4:8])[0]
        pos = 8
        id_len = 4 if version >= 1 else 2
        if count > (len(data) - pos) // (id_len + 1):
            self.problem(off, "count_beyond_box", "ipma declares %d entries and its bytes hold at most %d: the count is not believed" % (count, (len(data) - pos) // (id_len + 1)))
        for _ in range(min(count, MAX_ENTRIES)):
            if pos + id_len + 1 > len(data):
                break
            item_id = int.from_bytes(data[pos:pos + id_len], "big")
            n = data[pos + id_len]
            pos += id_len + 1
            width = 2 if flags & 1 else 1
            indexes = []
            for _a in range(n):
                if pos + width > len(data):
                    break
                raw = int.from_bytes(data[pos:pos + width], "big")
                indexes.append(raw & (0x7fff if width == 2 else 0x7f))
                pos += width
            self.assoc.setdefault(item_id, indexes)

    def iref(self, off, size, hdr):
        head = self.fullbox(off, size, hdr)
        if head is None:
            return
        wide = head[0] != 0
        idl = 4 if wide else 2
        for coff, csize, chdr, ctyp in self.boxes_in(off + hdr + 4, off + size, 2, "meta/iref"):
            data = self.body(coff, csize, chdr, 2 * idl + 2 + 4 * MAX_ENTRIES // 10)
            if len(data) < idl + 2:
                self.problem(coff, "iref_short", "a reference box too short for its header")
                continue
            source = int.from_bytes(data[:idl], "big")
            n = int.from_bytes(data[idl:idl + 2], "big")
            room = (len(data) - idl - 2) // idl
            if n > room:
                self.problem(coff, "count_beyond_box", "reference from item %d declares %d targets and the box holds %d" % (source, n, room))
                n = room
            targets = [int.from_bytes(data[idl + 2 + i * idl:idl + 2 + (i + 1) * idl], "big") for i in range(min(n, MAX_ENTRIES))]
            self.refs.setdefault(fourcc(ctyp), {}).setdefault(source, []).extend(targets)

    # --- what the walk found, as the answer states it ------------------------------------------------------------------------

    def property_of(self, item_id, kind):
        for index in self.assoc.get(item_id, []):
            if 1 <= index <= len(self.props) and self.props[index - 1][0] == kind:
                return self.props[index - 1][1]
        return None

    def item_bytes(self, item_id, length):
        loc = self.locations.get(item_id)
        if not loc or loc["method"] != 0 or not loc["extents"]:
            return None
        eoff, elen = loc["extents"][0]
        start = loc["base"] + eoff
        if elen < length:
            return None
        return self.rd.read(start, length)

    def grid(self, item_id):
        data = self.item_bytes(item_id, 8)
        if data is None or len(data) < 8:
            return None
        version, flags, rows, cols = data[0], data[1], data[2] + 1, data[3] + 1
        if flags & 1:
            more = self.item_bytes(item_id, 12)
            if more is None or len(more) < 12:
                return None
            return {"rows": rows, "columns": cols, "output_width": struct.unpack(">I", more[4:8])[0], "output_height": struct.unpack(">I", more[8:12])[0], "version": version}
        return {"rows": rows, "columns": cols, "output_width": struct.unpack(">H", data[4:6])[0], "output_height": struct.unpack(">H", data[6:8])[0], "version": version}

    def extents_checked(self):
        """Item data outside the file, and extents of different items that overlap."""
        beyond, spans = 0, []
        for item_id, loc in self.locations.items():
            if loc["method"] != 0:
                continue
            for eoff, elen in loc["extents"]:
                start = loc["base"] + eoff
                if elen and (start + elen > self.rd.size or start > self.rd.size):
                    beyond += 1
                    self.problem(start, "extent_beyond_file", "item %d has data at %d..%d and the file ends at %d" % (item_id, start, start + elen, self.rd.size))
                elif elen:
                    spans.append((start, start + elen, item_id))
        spans.sort()
        overlaps = 0
        high, high_item = -1, None
        for start, end, item_id in spans[:MAX_ENTRIES]:
            if start < high and item_id != high_item:
                overlaps += 1
                self.problem(start, "extents_overlap", "item %d starts at %d inside the data of item %s, which runs to %d" % (item_id, start, high_item, high))
            if end > high:
                high, high_item = end, item_id
        return beyond, overlaps

    def summary(self):
        beyond, overlaps = self.extents_checked()
        images = [i for i in self.item_order if self.items[i]["type"] in IMAGE_TYPES]
        visible = [i for i in images if not self.items[i]["hidden"]]
        primary = self.primary
        primary_info = None
        if primary is not None:
            item = self.items.get(primary)
            ispe = self.property_of(primary, "ispe")
            irot = self.property_of(primary, "irot")
            primary_info = {"item_id": primary, "type": item["type"] if item else None, "in_iinf": item is not None,
                            "width": ispe["width"] if ispe else None, "height": ispe["height"] if ispe else None,
                            "rotation_degrees": irot["angle"] if irot else 0, "position_among_visible_images": (visible.index(primary) + 1) if primary in visible else None}
            if item and item["type"] == "grid":
                grid = self.grid(primary)
                if grid:
                    grid["tiles_referenced"] = len(self.refs.get("dimg", {}).get(primary, []))
                    primary_info["grid"] = grid
        return {"brands": self.brands, "handler": self.handler, "top_level_boxes": self.top[:50], "top_level_box_count": len(self.top),
                "primary": primary_info, "items_declared": self.declared_items, "items_listed": len(self.items),
                "image_items": len(images), "visible_image_items": len(visible), "hidden_image_items": len(images) - len(visible),
                "item_types": {t: sum(1 for i in self.items.values() if i["type"] == t) for t in sorted({i["type"] for i in self.items.values() if i["type"]})},
                "properties": len(self.props), "references": {k: sum(len(v) for v in d.values()) for k, d in self.refs.items()},
                "extents_beyond_file": beyond, "extents_overlapping": overlaps, "boxes_walked": self.boxes, "boxes_not_entered": self.not_entered,
                "walk_truncated_at_max_boxes": self.truncated, "problems": self.problem_count}


# --- the image's own size (a header read), the programs ------------------------------------------------------------------------------

def image_size(path):
    """(format, width, height) of a JPEG or PNG from its header, bounded; (None, None, None) when it is neither."""
    try:
        fd, info = open_regular(path)
    except (OSError, NotRegular):
        return None, None, None
    with os.fdopen(fd, "rb") as fh:
        head = fh.read(24)
        if head[:8] == b"\x89PNG\r\n\x1a\n" and len(head) >= 24:
            return "png", struct.unpack(">I", head[16:20])[0], struct.unpack(">I", head[20:24])[0]
        if head[:2] == b"\xff\xd8":
            fh.seek(2)
            data = fh.read(1 << 20)
            pos = 0
            while pos + 4 <= len(data):
                if data[pos] != 0xff:
                    pos += 1
                    continue
                marker = data[pos + 1]
                if marker in (0xd8, 0x01) or 0xd0 <= marker <= 0xd7 or marker == 0xff:
                    pos += 1 if marker == 0xff else 2
                    continue
                length = struct.unpack(">H", data[pos + 2:pos + 4])[0]
                if 0xc0 <= marker <= 0xcf and marker not in (0xc4, 0xc8, 0xcc) and pos + 9 <= len(data):
                    return "jpeg", struct.unpack(">H", data[pos + 7:pos + 9])[0], struct.unpack(">H", data[pos + 5:pos + 7])[0]
                pos += 2 + max(length, 2)
    return None, None, None


def hash_file(fd, size, deadline):
    digest, done = hashlib.sha256(), 0
    while True:
        chunk = os.pread(fd, COPY_CHUNK, done)
        if not chunk:
            break
        done += len(chunk)
        digest.update(chunk)
        if time.monotonic() > deadline:
            raise OutOfTime()
    return digest.hexdigest(), done


def tree_bytes(directory):
    """(bytes, files) under a directory the backend writes into, without following a link; the file count is bounded."""
    total, files = 0, 0
    stack = [directory]
    while stack:
        current = stack.pop()
        try:
            with os.scandir(current) as it:
                for entry in it:
                    files += 1
                    if files > MAX_WORK_FILES:
                        return total, files
                    try:
                        info = entry.stat(follow_symlinks=False)
                    except OSError:
                        continue
                    if stat.S_ISDIR(info.st_mode):
                        stack.append(entry.path)
                    else:
                        total += info.st_size
        except OSError:
            pass
    return total, files


def run_bounded(argv, work, stdout_path, stderr_path, seconds, cap_bytes, env):
    """Run a program in this tool's process group, its output in files that are watched. Returns (exit code or None, why it was ended or None,
    seconds). It is ended with what it started at the deadline, when what it wrote passes cap_bytes, and by a stop signal; a program that
    has ended and left something running is swept."""
    began = time.monotonic()
    ended = None
    with open(stdout_path, "wb") as so, open(stderr_path, "wb") as se:
        proc = spawn(argv, stdout=so, stderr=se, cwd=work, env=env)
        ACTIVE.append(proc)
        try:
            while True:
                try:
                    code = proc.wait(timeout=FLOOD_STEP)
                    break
                except subprocess.TimeoutExpired:
                    pass
                _sample(proc.pid)
                if time.monotonic() - began > seconds:
                    ended = "the time given to it ran out"
                else:
                    written, entries = tree_bytes(work)
                    if written > cap_bytes:
                        ended = "what it wrote passed %d bytes" % cap_bytes
                    elif entries > MAX_WORK_FILES:
                        # The walk stops counting at the bound, so bytes past it are not summed: the program is ended instead, and the answer says so.
                        ended = "it made more than %d entries in its work directory, past which its bytes are not counted" % MAX_WORK_FILES
                if ended:
                    kill_tree(proc)
                    proc.wait()
                    code = None
                    break
        except BaseException:
            kill_tree(proc)
            raise
        finally:
            ACTIVE.remove(proc)
    reap_orphans()
    return code, ended, time.monotonic() - began


def read_capped(path, cap):
    """(bytes, whether the file was longer than cap)."""
    try:
        fd, info = open_regular(path)
    except (OSError, NotRegular):
        return b"", False
    with os.fdopen(fd, "rb") as fh:
        data = fh.read(cap + 1)
    return data[:cap], len(data) > cap


def program_path(name):
    found = shutil.which(name)
    return os.path.abspath(found) if found else None


PILLOW_CHILD = r'''
import json, sys
src, out, fmt, index, quality, limit = sys.argv[1], sys.argv[2], sys.argv[3], int(sys.argv[4]), sys.argv[5], int(sys.argv[6])
from PIL import Image
import pillow_heif
pillow_heif.register_heif_opener()
Image.MAX_IMAGE_PIXELS = limit
im = Image.open(src)
frames = getattr(im, "n_frames", 1)
if index > 1:
    im.seek(index - 1)
im.load()
if fmt == "jpeg" and im.mode not in ("RGB", "L"):
    im = im.convert("RGB")
kwargs = {"quality": int(quality)} if (fmt == "jpeg" and quality != "-") else {}
im.save(out, format=fmt.upper(), **kwargs)
print(json.dumps({"width": im.size[0], "height": im.size[1], "frames": frames}))
'''


def program_group_problems(what, held=True):
    """Sentences for the answer's problems from the shared process block's verdict, for an answer that reports `what`. A process settle() ended means what the program
    wrote (or printed on a pipe it held) was cut where it was ended; where the absence of one cannot be proven (not Linux, PR_SET_CHILD_SUBREAPER refused) files a program
    wrote cannot be shown to be final. held=False is a tool that reports only what a program printed on a pipe: it is not held to the second rule (program_group still
    says why), but processes that were adopted and could not all be ended are still named."""
    verdict = process_verdict()
    found = []
    if verdict["left_behind"]:
        found.append("a program left %d process(es) running after it ended (in the tool's process group, in a session of its own, or after a double fork); the shared process block "
                     "stopped, killed and reaped them before %s were read, so what they would still have written is missing from %s" % (verdict["left_behind"], what, what))
    for why in verdict["unproven"]:
        if held or verdict["subreaper"]:
            found.append("%s: %s cannot be shown to be final" % (why, what))
    return found


def scrub_text(raw, cap=2000):
    text = raw[:cap].decode("utf-8", "replace")
    return scrub(" ".join(text.split()))


def main():
    started = time.monotonic()
    args = read_args()
    unknown = sorted(str(k) for k in args if k not in ARGUMENTS)
    if unknown:
        fail("the tool has no such argument: %s" % ", ".join(scrub(k) for k in unknown[:10]), arguments=list(ARGUMENTS))
    path = args.get("path")
    if not isinstance(path, str) or not path:
        fail("path is required: a HEIC or HEIF file")
    fmt = args.get("format", "jpeg")
    if fmt not in FORMATS:
        fail('format must be "jpeg" or "png"', format=scrub(str(fmt)))
    backend = args.get("backend", "heif-convert")
    if backend not in BACKENDS:
        fail('backend must be "heif-convert" or "pillow-heif"', backend=scrub(str(backend)))
    convert = args.get("convert", True)
    write_values = args.get("write_values", False)
    if not isinstance(convert, bool) or not isinstance(write_values, bool):
        fail("convert and write_values must be true or false")
    quality = args.get("quality")
    if quality is not None and (isinstance(quality, bool) or not isinstance(quality, int) or not 1 <= quality <= 100):
        fail("quality must be an integer from 1 to 100 (it applies to jpeg only)")
    image = args.get("image")
    if image is not None and (isinstance(image, bool) or not isinstance(image, int) or not 1 <= image <= 100000):
        fail("image must be a positive integer: the image to keep, counted as the backend numbers the images of the file (1 is the first)")
    max_pixels = positive(args, "max_pixels", DEFAULT_MAX_PIXELS, MAX_PIXELS_CAP)
    max_bytes = positive(args, "max_bytes", DEFAULT_MAX_BYTES, MAX_BYTES_CAP)
    max_output = positive(args, "max_output_bytes", MAX_PREVIEW_BYTES, 1 << 40)
    limit = positive(args, "limit", DEFAULT_LIMIT, 1 << 20)
    max_seconds = seconds(args, "max_seconds", DEFAULT_MAX_SECONDS, MAX_SECONDS_CAP)
    deadline = started + max_seconds
    if not os.path.exists(path):
        fail("no such file or directory", path=shown(path, False))
    try:
        fd, info = open_regular(path)
    except NotRegular:
        fail("the path is not a regular file", path=shown(path, False))
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            fail("the path is a symbolic link: it is not followed", path=shown(path, False))
        fail("the file could not be opened: %s" % describe(exc), path=shown(path, False))
    base, shown_base = output_base()
    refuse_linked_dir(str(base / "tool-output"), "tool-output")
    refuse_linked_dir(str(base / "heic_inspect"), "heic_inspect")
    if write_values:
        choose_values_name(str(base))      # only looks for a free name; nothing is made
    values = open_values(args)             # refused as JSON here, before anything is made, when write_values is not allowed
    size = info.st_size
    head = os.pread(fd, 12, 0)
    if len(head) < 12 or head[4:8] != b"ftyp":
        os.close(fd)
        fail("not an ISO base media file: there is no 'ftyp' box at offset 4, so this is not a HEIC or HEIF file", bytes=size)
    observations = []
    problems_why = []
    result = ResultFile(base, shown_base, [shown(os.path.realpath(path), False), size, fmt, backend, convert, write_values], limit, INLINE_BYTES)

    # --- the original: identity and the box walk ----------------------------------------------------------------------------
    try:
        digest, hashed = hash_file(fd, size, started + max_seconds * EXIFTOOL_STAGE)
    except OutOfTime:
        digest, hashed = None, None
        problems_why.append("the clock ran out while the original was being hashed")
    walk = Walk(Reader(fd, size, started + max_seconds * EXIFTOOL_STAGE), result.add)
    try:
        walk.top_level()
    except OutOfTime:
        problems_why.append("the clock ran out during the box walk")
    walked = walk.summary()
    if walk.truncated:
        problems_why.append("the walk stopped at %d boxes" % MAX_BOXES)
    if walk.problem_count:
        problems_why.append("the walk found %d problem(s) in the boxes (listed, with offsets, in the result file)" % walk.problem_count)
    brands = walk.brands
    known = brands and ({brands["major"]} | set(brands["compatible"])) & set(BRANDS)
    if not brands:
        problems_why.append("no ftyp box was read")
    elif not known:
        problems_why.append("none of the brands of the file is one of %s" % ", ".join(BRANDS))
    if walk.handler is not None and walk.handler != "pict":
        observations.append("the meta handler is %s, not pict" % scrub(walk.handler))
    if not walk.meta_seen:
        problems_why.append("the file has no meta box")
    primary = walked["primary"] if walked else None

    # --- the metadata, from the original, with exiftool ---------------------------------------------------------------------
    work = None
    metadata = {"status": "not_run"}
    scratch_root = base / "heic_inspect"
    try:
        scratch_root.mkdir(parents=True, exist_ok=True)
        work = Path(tempfile.mkdtemp(prefix=".work-", dir=str(scratch_root)))
    except OSError as exc:
        fail("the output directory could not be made: %s" % describe(exc))
    CLEANUP.append(lambda: shutil.rmtree(work, ignore_errors=True))
    CLEANUP.append(kill_all)
    env = {"PATH": os.environ.get("PATH", ""), "HOME": str(work), "TMPDIR": str(work), "LANG": "C", "LC_ALL": "C",
           **({"PYTHONPATH": os.environ["PYTHONPATH"]} if os.environ.get("PYTHONPATH") else {})}
    real = os.path.realpath(path)
    exif = program_path("exiftool")
    if exif is None:
        metadata = {"status": "unavailable", "reason": "exiftool is not on PATH in this image: no metadata of the original was read"}
        problems_why.append("exiftool is not available, so the original's metadata was not read")
    elif time.monotonic() > deadline:
        metadata = {"status": "not_run", "reason": "no time was left"}
    else:
        so, se = work / "exiftool.out", work / "exiftool.err"
        code, ended, took = run_bounded([exif, "-json", "-G1", "-a", "-struct", real], str(work), str(so), str(se), max(5.0, min(60.0, max_seconds * EXIFTOOL_STAGE)), MAX_LOG_BYTES, env)
        raw, over = read_capped(so, MAX_LOG_BYTES)
        if ended or code not in (0, 1) and not raw:
            metadata = {"status": "failed", "reason": "exiftool %s" % (("was ended: " + ended) if ended else "exited %s: %s" % (code, scrub_text(read_capped(se, 4000)[0]))), "exit_code": code}
            problems_why.append("exiftool did not finish: no metadata of the original was read")
        elif over:
            metadata = {"status": "too_large", "reason": "exiftool wrote more than %d bytes: not read" % MAX_LOG_BYTES}
            problems_why.append("the metadata of the original is larger than the tool reads")
        else:
            try:
                parsed = json.loads(raw.decode("utf-8", "replace") or "[]")
                tags = parsed[0] if isinstance(parsed, list) and parsed and isinstance(parsed[0], dict) else {}
                tags = {k: v for k, v in tags.items() if k != "SourceFile"}      # the path the tool gave it, not a tag of the file
            except ValueError:
                tags = None
            errors = [k for k in (tags or {}) if k.endswith(":Error")]
            if tags is None:
                metadata = {"status": "unreadable", "reason": "exiftool's output was not JSON"}
                problems_why.append("exiftool's output was not JSON")
            elif errors:
                metadata = {"status": "failed", "reason": "exiftool reported an error for the file", "exiftool_exit_code": code}
                problems_why.append("exiftool could not read the original")
            else:
                groups = {}
                for key in tags:
                    # Group names come from the file (an XMP namespace prefix is the file's own text): only the families exiftool itself
                    # defines are named, every other group is counted as "other", so no text of the file reaches the answer through a group.
                    group = key.split(":", 1)[0] if ":" in key else "(none)"
                    family = group.split("-", 1)[0]
                    label = family if family in KNOWN_GROUPS else "other"
                    groups[label] = groups.get(label, 0) + 1
                names = list(groups)
                has = lambda g: any(n.upper().startswith(g) for n in names)
                metadata = {"status": "ok", "source": "exiftool, run on the original (never on the preview)", "tags": len(tags),
                            "groups": dict(sorted(groups.items())),
                            "has_exif": has("EXIF") or has("IFD"), "has_xmp": has("XMP"), "has_gps_tags": any("GPS" in k.upper() for k in tags),
                            "values": ("written to the 0600 values file (write_values)" if write_values else
                                       "withheld: the answer carries presence and counts, no value; ask with write_values in a job run as secret output"),
                            "exiftool_exit_code": code}
                if values.enabled:
                    for key, value in tags.items():
                        group, _sep, name = key.partition(":")
                        values.add("tag", {"group": group, "tag": name}, value)

    # --- the preview, from one backend, after the guards ---------------------------------------------------------------------------
    preview = {"status": "not_requested"} if not convert else None
    conversion = None
    if convert:
        refusal = None
        width = primary["width"] if primary else None
        height = primary["height"] if primary else None
        if size > max_bytes:
            refusal = "the original is %d bytes, over max_bytes (%d): no conversion was started" % (size, max_bytes)
        elif not width or not height:
            refusal = "the container does not declare the primary image's size (no ispe is associated with the primary item), so the pixel guard cannot be applied: no conversion was started"
        elif width * height > max_pixels:
            refusal = "the primary image declares %d x %d pixels (%d), over max_pixels (%d): no conversion was started" % (width, height, width * height, max_pixels)
        if refusal is None:
            program = program_path("heif-convert") if backend == "heif-convert" else sys.executable
            if program is None:
                refusal = "the backend heif-convert is not on PATH in this image: nothing was converted, and no other backend is tried"
        if refusal is not None:
            preview = {"status": "refused", "reason": refusal, "backend": backend}
            problems_why.append("no preview: " + refusal)
        else:
            left = deadline - time.monotonic()
            allowed = max(1.0, min(left * 0.9, max_seconds * 0.5))
            out_name = "preview-%s%s.%s" % ((digest or "unhashed")[:16], "-img%d" % image if image else "", "jpg" if fmt == "jpeg" else "png")
            bout = work / ("out." + ("jpg" if fmt == "jpeg" else "png"))
            if backend == "heif-convert":
                argv = [program] + (["-q", str(quality)] if quality is not None and fmt == "jpeg" else []) + [real, str(bout)]
            else:
                argv = [program, "-c", PILLOW_CHILD, real, str(bout), fmt, str(image or 1), str(quality) if quality is not None else "-", str(max_pixels)]
            so, se = work / "backend.out", work / "backend.err"
            code, ended, took = run_bounded(argv, str(work), str(so), str(se), allowed, max_output, env)
            produced = sorted(p for p in work.iterdir() if p.is_file() and not p.is_symlink() and p.name.startswith("out") and p.suffix in (".jpg", ".png"))
            conversion = {"backend": backend, "program": "heif-convert" if backend == "heif-convert" else "pillow-heif (python child)", "format": fmt,
                          "quality": quality if (quality is not None and fmt == "jpeg") else "the backend's default", "image_requested": image or "primary",
                          "exit_code": code, "ended": ended, "seconds": round(took, 3), "files_produced": len(produced),
                          "errors": scrub_text(read_capped(se, 4000)[0]), "output": scrub_text(read_capped(so, 4000)[0], 500)}
            chosen, why = None, None
            if ended:
                why = "the backend was ended: %s" % ended
            elif code != 0:
                why = "the backend exited %s" % code
            elif not produced:
                why = "the backend exited 0 and wrote no image"
            elif len(produced) == 1:
                chosen = produced[0]
            else:
                want = image or (primary.get("position_among_visible_images") if primary else None)
                if image is None and (want is None or len(produced) != walked["visible_image_items"]):
                    why = ("the backend wrote %d images and the primary could not be matched to one (the file has %d visible image items): name the image to keep" %
                           (len(produced), walked["visible_image_items"]))
                else:
                    pick = [p for p in produced if re.fullmatch(r"out-%d\.(jpg|png)" % want, p.name)]
                    if len(pick) == 1:
                        chosen = pick[0]
                    else:
                        why = "the backend wrote %d images and none is number %s" % (len(produced), want)
                if chosen is not None:
                    conversion["images_written_by_the_backend"] = len(produced)
            if chosen is None:
                preview = {"status": "failed", "reason": why, "backend": backend}
                problems_why.append("no preview: " + why)
            else:
                final_dir = scratch_root
                try:
                    placed = place_without_replacing(chosen, final_dir / out_name)
                except OSError as exc:
                    placed = None
                    preview = {"status": "failed", "reason": "the preview could not be placed: %s" % describe(exc), "backend": backend}
                    problems_why.append("the preview could not be placed")
                if placed is not None:
                    kind, pw, ph = image_size(str(placed))
                    dsha, dsize = None, None
                    try:
                        dfd, dinfo = open_regular(str(placed))
                        try:
                            dsha, dsize = hash_file(dfd, dinfo.st_size, deadline + 5)
                        finally:
                            os.close(dfd)
                    except (OSError, NotRegular, OutOfTime):
                        pass
                    preview = {"status": "written", "path": shown_base + "/heic_inspect/" + placed.name, "format": kind, "bytes": dsize, "sha256": dsha,
                               "width": pw, "height": ph, "backend": backend,
                               "matches_declared_size": None if not (pw and ph and width and height) else
                               (pw, ph) in ((width, height), (height, width)),
                               "note": "a derivative of the original: its own metadata is not the original's and is not read here; the original's metadata is the exiftool block"}
                    if placed.name != out_name:
                        preview["earlier_file_kept"] = shown_base + "/heic_inspect/" + out_name
                    if kind is None:
                        problems_why.append("the preview is neither a JPEG nor a PNG by its header")
                    elif pw and ph and width and height and (pw, ph) not in ((width, height), (height, width)):
                        observations.append("the preview is %d x %d and the original declares %d x %d for its primary image (a selected image or a transform may differ)" % (pw, ph, width, height))
    try:
        values.close()
    except Exception:
        pass
    os.close(fd)
    shutil.rmtree(work, ignore_errors=True)

    # --- the answer -----------------------------------------------------------------------------------------------------------
    paging = result.finish()
    # exiftool's output and the preview are files a program wrote: a process either left behind (ended by settle() before they were read, sized and hashed), or one that
    # cannot be ruled out (not Linux, PR_SET_CHILD_SUBREAPER refused), keeps the answer from `complete`
    problems_why.extend(program_group_problems("exiftool's output and the preview"))
    complete = not problems_why and (not convert or (preview is not None and preview["status"] == "written"))
    answer = {
        "path": shown(path), "parser": PARSER,
        "status": "complete" if complete else "partial",
        "status_basis": ("the boxes of the original were walked to their end with no problem, its metadata was read with exiftool, and %s"
                         % ("the preview was written by the one backend named" if convert else "no preview was asked for (convert was false)")) if complete
        else "partial because " + "; ".join(problems_why),
        "original": {"bytes": size, "sha256": digest, "container": "ISO base media file (ftyp at offset 4)", "brands": brands,
                     "brand_read": bool(known), "walk": walked},
        "metadata": metadata,
        "preview": preview, "conversion": conversion,
        "guards": {"max_pixels": max_pixels, "max_bytes": max_bytes,
                   "applied_before_conversion": "the original's size, and the pixel count of its own primary ispe; a file that declares no size is refused"},
        "values_file": {"requested": write_values, "written": values.written, "file": values.shown if write_values else None},
        "observations": observations,
        "boxes": result.page, "box_rows": result.rows, "problems": walk.problems, "problem_count": walk.problem_count,
        "pages": {"boxes": paging}, "truncated": paging["truncated"] or walk.problem_count > len(walk.problems),
        "note": "The preview is a derivative of the original. Identity, dimensions, brands and the structure come from the original's own boxes (a bounded "
                "standard-library walk, no decoder); the metadata comes from exiftool on the original, never from the preview. The pixel and size guards "
                "run before any backend is started. heif-convert writes one file per image of the file; the tool keeps the one asked for (image) or, by "
                "default, the primary, and says when it cannot tell which.",
    }
    CLEANUP.clear()
    process_apply(answer)       # program_group; a complete answer cannot have got here with a leftover
    send(answer)


if __name__ == "__main__":
    run_main(main)
