#!/usr/bin/env python3
"""Map an unencrypted Android adb backup (.ab) onto the layout ALEAPP reads, and call the result what it is: a derivative of an adb backup.

An `.ab` file is a text header (`ANDROID BACKUP`, a format version, a compression flag, an encryption scheme) and then a tar, deflated
with zlib when the flag says so. The tar's members are named by the backup agent, not by the phone's file system:

    apps/<package>/_manifest              the package's own manifest record
    apps/<package>/<domain>/<path>        a file of the package, where <domain> is a FullBackup token (a, obb, r, f, db, sp, nb, c, ef,
                                          and the device-protected forms d_r, d_f, d_db, d_sp, d_nb, d_c)
    shared/<n>/<path>                     shared storage, when the backup was asked for it

This streams the tar once, with the end of the zlib stream, the tar's two end blocks and the bytes after them all verified, and for a
selection writes under `$OUT/ab_layout/derivative`:

    data/data/<package>/{files,databases,shared_prefs,no_backup,cache}/...   domains f, db, sp, nb, c; domain r is the package root
    data/user_de/0/<package>/...                                             the d_ forms
    ab_layout_meta/<package>/_manifest                                       the manifest record, kept apart from the data tree
    DERIVATIVE.json                                                          the banner: a derivative of an adb backup

The mapping table is in the manifest, with its basis. The derivative is NEVER an acquisition of the file system: the banner and the answer
say "derivative of an adb backup". Members the tool does not extract (the APK, obb, external storage, shared storage, links, devices,
directories) are listed, never written; a member name that is hostile (`..` as a component, an absolute path, an empty component, a NUL,
an over-long name) is rejected and listed; a name that is only odd (`..config`) is a file name. Two members on one name each get their own
(case-folding ones included). Nothing is written outside `$OUT`, and no password is read or accepted: an encrypted backup is refused.

THE SECRET-SAFE OUTPUT PATTERN. Writing app data writes what the backup holds, and that can be secret. `copy_content` is false by default
(a plan: the whole inventory with the mapping, nothing extracted) and is a `secret_output` mode of the manifest: accepted only in a job run
as secret output (SECRET_OUTPUT=1), otherwise refused as JSON before anything is made. A path component shaped like a recovery password is
withheld from every channel (the answer, the result file, the names under the derivative); its real member name is written only to the 0600
values file of a `copy_content` job.
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
import sqlite3
import stat
import struct
import sys
import tempfile
import time
import unicodedata
import zlib
import datetime
import plistlib
import warnings
from pathlib import Path

PARSER = "ab_layout/3"
TOOL = "ab_layout"
VALUES_NAME = "ab-layout-values.jsonl"       # the first free name of this and -2, -3 ... is used (see choose_values_name)
VALUES_FORMAT = "JSON Lines: the member name and the id of each member whose name is withheld"


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


# --- ab_layout ----------------------------------------------------------------------------------------------------------------------

MAGIC = b"ANDROID BACKUP\n"
SUPPORTED_VERSIONS = (1, 2, 3, 4, 5)
DEFAULT_LIMIT = 200
INLINE_BYTES = 1 << 20
DEFAULT_MAX_SECONDS = 240
MAX_SECONDS_CAP = 255       # manifest.json timeout_seconds (300) less the work after the loop and the time to write the answer
COPY_SHARE = 0.93
PIECE = 1 << 20
DEFAULT_MAX_MEMBERS = 200000
MAX_MEMBERS_CAP = 1000000
DEFAULT_MAX_BYTES = 4 << 30
MAX_BYTES_CAP = 1 << 42
DEFAULT_MAX_DECOMPRESSED = 16 << 30
MAX_DECOMPRESSED_CAP = 1 << 42
COMPONENT_BYTES = 255
PATH_BYTES = 4096
MAX_COMPONENTS = 64
MAX_CLAIMS = 2000000
EXTENDED_LIMIT = 1 << 20       # a pax or GNU long-name record larger than this is not read: the walk stops
MAX_PACKAGES = 100000
PLACEHOLDER = "withheld-component"
ZERO = b"\0" * 512
ARGUMENTS = ("path", "copy_content", "packages", "max_members", "max_bytes", "max_decompressed_bytes", "max_seconds", "limit")
PACKAGE = re.compile(r"[A-Za-z0-9_.-]{1,255}\Z")
SQLITE_SUFFIXES = ("-wal", "-shm", "-journal")

# The mapping of a FullBackup domain token onto the layout ALEAPP reads: (root under the derivative, sub-directory of the package, what it is).
# The basis is written in the manifest. A token not in this table, and not in NOT_LAID_OUT, is an unknown domain: listed, not extracted, partial.
DOMAINS = {
    "r": ("data/data", "", "the package's root directory"),
    "f": ("data/data", "files", "files/"),
    "db": ("data/data", "databases", "databases/"),
    "sp": ("data/data", "shared_prefs", "shared_prefs/"),
    "nb": ("data/data", "no_backup", "no_backup/"),
    "c": ("data/data", "cache", "cache/"),
    "d_r": ("data/user_de/0", "", "the package's device-protected root"),
    "d_f": ("data/user_de/0", "files", "device-protected files/"),
    "d_db": ("data/user_de/0", "databases", "device-protected databases/"),
    "d_sp": ("data/user_de/0", "shared_prefs", "device-protected shared_prefs/"),
    "d_nb": ("data/user_de/0", "no_backup", "device-protected no_backup/"),
    "d_c": ("data/user_de/0", "cache", "device-protected cache/"),
}
NOT_LAID_OUT = {"a": "the application package (APK)", "obb": "the expansion files (obb)", "ef": "external storage files of the package"}
TYPES = {b"0": "file", b"\0": "file", b"7": "file", b"1": "hardlink", b"2": "symlink", b"3": "character_device", b"4": "block_device",
         b"5": "directory", b"6": "fifo", b"S": "sparse", b"x": "pax", b"g": "pax_global", b"L": "gnu_longname", b"K": "gnu_longlink"}
STATES_PROBLEM = ("rejected_name", "unknown_domain", "outside_layout", "not_extracted_max_bytes", "layout_full", "write_failed",
                  "truncated_member", "not_attempted_max_seconds", "not_attempted_write_stopped", "sparse_not_extracted", "pax_unreadable")


class OutOfTime(Exception):
    pass


class Budget(Exception):
    def __init__(self, which):
        Exception.__init__(self, which)
        self.which = which


class TreeFull(Exception):
    pass


class StreamEnded(Exception):
    """The payload ended (or its budget did) in the middle of something the tar parser needed."""


def fd_flags(extra=0):
    return os.O_RDONLY | extra | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)


def output_base():
    job, out = os.environ.get("JOB_ID"), os.environ.get("OUT")
    if job and out:
        return Path(out), "store/jobs/%s/out" % safe_name(job)
    base = Path("work") / safe_name(os.environ.get("AGENT_ID") or "tool")
    return base, str(base)


class ResultFile:
    """One line per member, written as it is known and flushed at once, so that the count the answer gives is the lines the file holds,
    whatever ends the run. The inline page is a prefix. The file takes its name without replacing an earlier one (PLACE); the hidden
    temporary is registered for removal before it exists and is removed by a failure and by a stop."""

    def __init__(self, base, shown_base, key, limit, byte_limit):
        self.limit, self.byte_limit = limit, byte_limit
        self.page, self.page_bytes, self.rows, self.bytes_bound_hit = [], 0, 0, False
        digest = hashlib.sha256(dumps([key, NONCE], sort_keys=True).encode("utf-8")).hexdigest()[:16]
        name = "%s-%s.jsonl" % (TOOL, digest)
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
                  "all_results_format": "JSON Lines, one member of the backup's tar per line"}
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


def make_dirs_nofollow(path):
    os.makedirs(path, mode=0o700, exist_ok=True)
    walk = Path(path)
    while walk != walk.parent and str(walk) not in (".", ""):
        if walk.is_symlink():
            raise OSError(errno.ELOOP, "a symbolic link in the output path", str(walk))
        walk = walk.parent


def choose_values_name(out):
    global VALUES_NAME
    stem = "ab-layout-values"
    for n in range(1, 1000):
        name = "%s%s.jsonl" % (stem, "" if n == 1 else "-%d" % n)
        if not os.path.lexists(os.path.join(out, name)):
            VALUES_NAME = name
            return
    fail("no free name for the values file in the output directory")


def b64(raw):
    return base64.b64encode(raw).decode("ascii")


def text_of(raw):
    return raw.decode("utf-8", "surrogateescape")


def nbytes(text):
    return len(text.encode("utf-8", "surrogateescape"))


def fold(text):
    return unicodedata.normalize("NFC", text).casefold()


def vary(name, n, is_file):
    stem, suffix = os.path.splitext(name) if is_file else (name, "")
    extra = "-%d%s" % (n, suffix)
    room = COMPONENT_BYTES - nbytes(extra)
    raw = stem.encode("utf-8", "surrogateescape")
    if len(raw) > room:
        stem = raw[:max(room, 1)].decode("utf-8", "surrogateescape")
    return stem + extra


class Tree:
    """The names the layout holds, so that two members never meet on one name, case-folding ones included. Keyed by a digest chain of the
    folded components (memory is linear in the names, not their depth). A directory met again in another spelling is the first spelling. A
    file whose name is taken, as a file or a directory, takes name-2, name-3 ...; the next number to try is remembered per name."""

    def __init__(self):
        self.claimed = {}

    def resolve(self, parts):
        final, notes, key = [], [], b""
        for i, part in enumerate(parts):
            last = i == len(parts) - 1
            name = part
            origin = None
            while True:
                k = hashlib.blake2b(key + b"\0" + fold(name).encode("utf-8", "surrogatepass"), digest_size=16).digest()
                have = self.claimed.get(k)
                if have is None:
                    if len(self.claimed) >= MAX_CLAIMS:
                        raise TreeFull()
                    self.claimed[k] = ["file" if last else "dir", name, 2]
                    break
                if not last and have[0] == "dir":
                    if have[1] != part:
                        notes.append({"kind": "case_fold", "component": i})
                    name = have[1]
                    break
                if origin is None:
                    origin = have
                    notes.append({"kind": ("duplicate_path" if have[1] == part else "case_fold") if (last and have[0] == "file") else "file_vs_directory", "component": i})
                name = vary(part, origin[2], last)
                origin[2] += 1
            final.append(name)
            key = k
        return final, notes


def ensure_dir(root_fd, parts):
    fd = os.dup(root_fd)
    try:
        for part in parts:
            try:
                os.mkdir(part, 0o700, dir_fd=fd)
            except FileExistsError:
                pass
            nxt = os.open(part, fd_flags(os.O_DIRECTORY), dir_fd=fd)
            os.close(fd)
            fd = nxt
        return fd
    except BaseException:
        os.close(fd)
        raise


TEMP_COUNTER = [0]


def write_member(src, size, files_fd, files_path, parts, budget_left, deadline, progress):
    """Stream `size` bytes of the tar into files/<parts> without replacing anything: a hidden temporary beside the name (registered for removal
    before it is made), then PLACE. Returns (path it holds, sha256). Raises StreamEnded when the payload ends first (the temporary is removed),
    Budget past the bytes or the clock."""
    dir_fd = ensure_dir(files_fd, parts[:-1])
    TEMP_COUNTER[0] += 1
    tmp_name = ".ab-%s-%d.tmp" % (NONCE, TEMP_COUNTER[0])
    directory = os.path.join(files_path, *parts[:-1]) if len(parts) > 1 else files_path
    tmp_path = os.path.join(directory, tmp_name)

    def remove():
        try:
            os.unlink(tmp_path)
        except FileNotFoundError:
            pass
    CLEANUP.append(remove)
    out_fd = None
    try:
        out_fd = os.open(tmp_name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0), 0o600, dir_fd=dir_fd)
        digest, left = hashlib.sha256(), size
        if size > budget_left:
            raise Budget("max_bytes")
        while left > 0:
            if time.monotonic() > deadline:
                raise Budget("max_seconds")
            chunk = src.read(min(left, PIECE))
            if not chunk:
                raise StreamEnded()
            left -= len(chunk)
            progress[0] += len(chunk)
            digest.update(chunk)
            view = memoryview(chunk)
            while len(view):
                view = view[os.write(out_fd, view):]
        os.close(out_fd)
        out_fd = None
        placed = place_without_replacing(Path(tmp_path), Path(directory) / parts[-1])
        return placed, digest.hexdigest()
    finally:
        if out_fd is not None:
            os.close(out_fd)
        os.close(dir_fd)
        remove()
        if remove in CLEANUP:
            CLEANUP.remove(remove)


def write_banner(derivative_path, banner):
    text = (json.dumps(banner, sort_keys=True, indent=2) + "\n").encode("utf-8")
    fd, name = tempfile.mkstemp(dir=derivative_path, prefix=".ab-banner-")
    tmp = Path(name)
    CLEANUP.append(lambda: tmp.unlink() if tmp.exists() else None)
    with os.fdopen(fd, "wb") as fh:
        fh.write(text)
    return place_without_replacing(tmp, Path(derivative_path) / "DERIVATIVE.json")


# --- the payload and the tar ----------------------------------------------------------------------------------------------------

class Source:
    """The decompressed payload, read in pieces under a byte budget and the clock, however it is compressed. `read(n)` returns n bytes, or fewer
    at the end of the payload; the reasons it ended are kept. A 1 KB stream that expands to 2 GB is stopped at the budget, and what was read is
    all that is ever held (one piece)."""

    def __init__(self, fd, size, offset, compressed, budget, deadline):
        self.fd, self.size, self.file_pos = fd, size, offset
        self.d = zlib.decompressobj() if compressed else None
        self.budget, self.deadline = budget, deadline
        self.buf = bytearray()
        self.pos = 0                    # offset in the decompressed payload of the next byte read()
        self.produced = 0
        self.done = False
        self.state = "reading"          # reached | not_reached (budget or clock) | truncated | damaged | reading
        self.tail = b""
        self.after = 0                  # bytes after the end of the zlib stream
        self.error = None

    def _more(self):
        if self.done:
            return False
        if time.monotonic() > self.deadline:
            self.state, self.done = "not_reached", True
            self.error = "the clock"
            return False
        room = self.budget - self.produced
        if room <= 0:
            self.state, self.done, self.error = "not_reached", True, "the decompression budget"
            return False
        if self.d is None:
            chunk = os.pread(self.fd, min(PIECE, room), self.file_pos)
            if not chunk:
                self.state, self.done = "reached", True
                return False
            self.file_pos += len(chunk)
            self.produced += len(chunk)
            self.buf += chunk
            return True
        data = self.tail
        if not data:
            data = os.pread(self.fd, PIECE, self.file_pos)
            self.file_pos += len(data)
            if not data:
                self.state, self.done = "truncated", True
                return False
        try:
            out = self.d.decompress(data, min(PIECE, room))
        except zlib.error as exc:
            self.state, self.done, self.error = "damaged", True, str(exc)[:200]
            return False
        self.tail = self.d.unconsumed_tail
        self.produced += len(out)
        self.buf += out
        if self.d.eof:
            self.state, self.done = "reached", True
            self.after = len(self.d.unused_data) + max(self.size - self.file_pos, 0)
        return True

    def read(self, n):
        while len(self.buf) < n and self._more():
            pass
        out = bytes(self.buf[:n])
        del self.buf[:n]
        self.pos += len(out)
        return out

    def skip(self, n):
        """Read and discard n bytes in pieces; the number discarded."""
        got = 0
        while got < n:
            chunk = self.read(min(PIECE, n - got))
            if not chunk:
                break
            got += len(chunk)
        return got


def cstr(raw):
    end = raw.find(b"\0")
    return raw if end < 0 else raw[:end]


def tar_number(field):
    """A tar numeric field: octal text, or base-256 when the top bit of the first byte is set. None for a field that is neither."""
    if field and field[0] & 0x80:
        if field[0] & 0x40:
            return None          # a negative number
        return int.from_bytes(bytes([field[0] & 0x7f]) + field[1:], "big")
    text = cstr(field).strip(b" \0")
    if not text:
        return 0
    if not re.fullmatch(rb"[0-7]+", text):
        return None
    return int(text, 8)


def parse_header(block):
    """A tar header as a dict, or None when its checksum does not hold or a number does not parse."""
    stored = tar_number(block[148:156])
    if stored is None or stored != sum(block[:148]) + 8 * 32 + sum(block[156:]):
        return None
    size = tar_number(block[124:136])
    mode, mtime = tar_number(block[100:108]), tar_number(block[136:148])
    if size is None or mode is None or mtime is None:
        return None
    name = cstr(block[0:100])
    if block[257:262] == b"ustar":
        prefix = cstr(block[345:500])
        if prefix:
            name = prefix + b"/" + name
    return {"name": name, "size": size, "mode": mode, "mtime": mtime, "type": block[156:157], "linkname": cstr(block[157:257])}


def pax_records(data):
    """The key/value records of a pax extended header: {key: value bytes}, or None when the records do not parse."""
    out, pos = {}, 0
    while pos < len(data):
        space = data.find(b" ", pos)
        if space < 0 or not data[pos:space].isdigit():
            return None
        length = int(data[pos:space])
        if length <= space - pos + 1 or pos + length > len(data) or data[pos + length - 1:pos + length] != b"\n":
            return None
        record = data[space + 1:pos + length - 1]
        key, eq, value = record.partition(b"=")
        if not eq:
            return None
        out[key] = value
        pos += length
    return out


def classify_name(name):
    """(kind, package, domain, rest, why): what a member name says it is, under apps/<package>/ or shared/. kind is apps, shared, manifest,
    rejected or other."""
    if "\0" in name:
        return "rejected", None, None, None, "the name holds a NUL"
    if nbytes(name) > PATH_BYTES:
        return "rejected", None, None, None, "a name of over %d bytes" % PATH_BYTES
    if name.startswith("/"):
        return "rejected", None, None, None, "an absolute path"
    parts = name.rstrip("/").split("/") if name not in ("", "/") else [""]
    if len(parts) > MAX_COMPONENTS:
        return "rejected", None, None, None, "more than %d components" % MAX_COMPONENTS
    for part in parts:
        if part in ("", ".", ".."):
            return "rejected", None, None, None, "a component that is empty, '.' or '..'"
        if nbytes(part) > COMPONENT_BYTES:
            return "rejected", None, None, None, "a component of over %d bytes" % COMPONENT_BYTES
    if parts[0] == "apps":
        if len(parts) < 2:
            return "other", None, None, None, None
        if not PACKAGE.fullmatch(parts[1]) or parts[1] in (".", ".."):
            return "rejected", None, None, None, "a package name that is not an Android package name"
        if len(parts) == 3 and parts[2] == "_manifest":
            return "manifest", parts[1], "_manifest", [], None
        if len(parts) >= 3:
            return "apps", parts[1], parts[2], parts[3:], None
        return "apps", parts[1], None, [], None
    if parts[0] == "shared":
        return "shared", None, None, parts[1:], None
    return "other", None, None, parts, None


def main():
    started = time.monotonic()
    args = read_args()
    unknown = sorted(str(k) for k in args if k not in ARGUMENTS)
    if unknown:
        fail("the tool has no such argument: %s" % ", ".join(scrub(k) for k in unknown[:10]), arguments=list(ARGUMENTS))
    path = args.get("path")
    if not isinstance(path, str) or not path:
        fail("path is required: an Android backup (.ab) file")
    copy_content = args.get("copy_content", False)
    if not isinstance(copy_content, bool):
        fail("copy_content must be true or false")
    packages = args.get("packages")
    if packages is not None and (not isinstance(packages, list) or len(packages) > 1000 or not all(isinstance(p, str) and PACKAGE.fullmatch(p) for p in packages)):
        fail("packages must be a list of at most 1000 Android package names")
    wanted = set(packages) if packages else None
    max_members = positive(args, "max_members", DEFAULT_MAX_MEMBERS, MAX_MEMBERS_CAP)
    max_bytes = positive(args, "max_bytes", DEFAULT_MAX_BYTES, MAX_BYTES_CAP)
    max_decompressed = positive(args, "max_decompressed_bytes", DEFAULT_MAX_DECOMPRESSED, MAX_DECOMPRESSED_CAP)
    limit = positive(args, "limit", DEFAULT_LIMIT, 1 << 20)
    max_seconds = seconds(args, "max_seconds", DEFAULT_MAX_SECONDS, MAX_SECONDS_CAP)
    deadline = started + max_seconds * COPY_SHARE
    if copy_content:
        if not (os.environ.get("JOB_ID") and os.environ.get("OUT")):
            fail("copy_content is refused outside a job: app data written here would be an ordinary file, not a sealed secret output. "
                 "Run this as job_run tool=%s with secret_output: true, and ask again there. Nothing was written." % TOOL, copy_content="refused", written=False)
        if os.environ.get("SECRET_OUTPUT") != "1":
            fail("copy_content is refused in a job that is not run as secret output (SECRET_OUTPUT is not 1). Run this as job_run tool=%s with "
                 "secret_output: true, and ask again there. Nothing was written." % TOOL, copy_content="refused", written=False)
    if not os.path.exists(path):
        fail("no such file or directory", path=shown(path, False))
    try:
        fd = os.open(path, fd_flags())
        info = os.fstat(fd)
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            fail("the path is a symbolic link: it is not followed", path=shown(path, False))
        fail("the file could not be opened: %s" % describe(exc), path=shown(path, False))
    if not stat.S_ISREG(info.st_mode):
        os.close(fd)
        fail("the path is not a regular file", path=shown(path, False))
    size = info.st_size

    # --- the header: read, never trusted ------------------------------------------------------------------------------------
    head = os.pread(fd, 4096, 0)
    if not head.startswith(MAGIC):
        os.close(fd)
        fail("not an Android backup: the file does not start with 'ANDROID BACKUP'", bytes=size)
    lines = head.split(b"\n", 4)
    if len(lines) < 5:
        os.close(fd)
        fail("the backup's header is cut short or longer than 4096 bytes: it is not read", bytes=size)
    version_text, compressed_text, scheme = lines[1], lines[2], lines[3]
    if not re.fullmatch(rb"[0-9]{1,4}", version_text) or compressed_text not in (b"0", b"1") or not re.fullmatch(rb"[A-Za-z0-9._-]{1,16}", scheme):
        os.close(fd)
        fail("the backup's header lines are not a version, a compression flag 0 or 1 and an encryption scheme", bytes=size)
    version, compressed, scheme_text = int(version_text), compressed_text == b"1", scheme.decode("ascii")
    header = {"version": version, "compressed": compressed, "encryption": scheme_text}
    if scheme != b"none":
        os.close(fd)
        fail("the payload is encrypted (%s): this tool reads the header only, opens nothing and reads no password" % scheme_text,
             header=header, status_detail="encrypted")
    if version not in SUPPORTED_VERSIONS:
        os.close(fd)
        fail("header version %d is not one this tool reads (%s): unsupported, and nothing but the header is reported" % (version, ", ".join(map(str, SUPPORTED_VERSIONS))),
             header=header, status_detail="unsupported")
    payload_at = len(MAGIC) + len(version_text) + len(compressed_text) + len(scheme) + 3

    base, shown_base = output_base()
    refuse_linked_dir(str(base / "tool-output"), "tool-output")
    result = ResultFile(base, shown_base, [shown(os.path.realpath(path), False), size, copy_content, sorted(wanted) if wanted else None], limit, INLINE_BYTES)
    values = None
    if copy_content:
        try:
            base.mkdir(parents=True, exist_ok=True)
            choose_values_name(str(base))
            values = SecretValues(True)
        except SecretValuesRefused as exc:
            fail(str(exc), copy_content="refused", written=False)
        except OSError as exc:
            fail("the output directory could not be made: %s" % describe(exc))
    files_fd, files_path, derivative_path = None, None, None
    if copy_content:
        try:
            derivative_path = str(base / "ab_layout" / "derivative")
            make_dirs_nofollow(derivative_path)
            files_path = derivative_path
            files_fd = os.open(derivative_path, fd_flags(os.O_DIRECTORY))
            write_banner(derivative_path, BANNER)
        except OSError as exc:
            fail("the derivative directory could not be made: %s" % describe(exc))

    src = Source(fd, size, payload_at, compressed, max_decompressed, deadline)
    tree = Tree()
    counts = {"members_read": 0, "extracted_files": 0, "extracted_bytes": 0, "states": {}, "domains": {}, "name_collisions": 0, "names_withheld": 0,
              "sqlite_companions": 0, "sqlite_companions_without_base": 0}
    package_counts = {}
    sqlite_bases, sqlite_companions = set(), []
    observations = []
    problems = []
    collisions = []
    tar_end = "missing"
    lone_zero = 0
    zeros = 0
    stop_reason = None
    write_stopped = False
    out_of_bytes = False
    clock_stopped = False
    bytes_left = max_bytes
    extended = {}              # pax/GNU long-name overrides for the next member
    data_after_end = 0

    def note(text):
        if len(problems) < 25:
            problems.append(text)

    try:
        while True:
            if counts["members_read"] >= max_members:
                stop_reason = "max_members (%d) reached: the rest of the payload is not read" % max_members
                tar_end = "not_reached"
                break
            offset = src.pos
            block = src.read(512)
            if not block:
                break
            if len(block) < 512:
                note("the payload ends %d bytes into a tar header" % len(block))
                tar_end = "truncated"
                break
            if block == ZERO:
                zeros += 1
                if zeros == 2:
                    tar_end = "reached"
                    break
                continue
            if zeros == 1:
                lone_zero += 1
            zeros = 0
            h = parse_header(block)
            if h is None:
                note("a tar header at payload offset %d does not hold (checksum or number): the walk stops, as nothing after it can be found" % offset)
                tar_end = "damaged"
                break
            kind = TYPES.get(h["type"], "other")
            size_m = h["size"]
            if h["type"] == b"S" and block[482]:
                # An old GNU sparse header: extension blocks of the map sit between the header and the data. They are passed over, so the data
                # is skipped from where it is (the member itself is listed and never extracted).
                extension_blocks = 0
                while True:
                    ext = src.read(512)
                    extension_blocks += 1
                    if len(ext) < 512:
                        note("the payload ends inside the sparse map of a member at offset %d" % offset)
                        tar_end = "truncated"
                        break
                    if not ext[504]:
                        break
                    if extension_blocks >= 65536:
                        note("the sparse map of the member at offset %d has more than 65536 extension blocks: the walk stops" % offset)
                        tar_end = "damaged"
                        break
                if tar_end in ("truncated", "damaged"):
                    break
            if kind in ("pax", "pax_global", "gnu_longname", "gnu_longlink"):
                if size_m > EXTENDED_LIMIT:
                    note("an extended header of %d bytes at payload offset %d is over the %d this tool reads: the walk stops" % (size_m, offset, EXTENDED_LIMIT))
                    tar_end = "damaged"
                    break
                data = src.read(size_m)
                pad = (-size_m) % 512
                if len(data) < size_m or src.skip(pad) < pad:
                    note("the payload ends inside an extended header at offset %d" % offset)
                    tar_end = "truncated"
                    break
                if kind == "pax":
                    records = pax_records(data)
                    if records is None:
                        note("a pax header at payload offset %d does not parse: its member keeps the name in its own header" % offset)
                        extended["bad"] = True
                    else:
                        if b"path" in records:
                            extended["name"] = records[b"path"]
                        if b"linkpath" in records:
                            extended["linkname"] = records[b"linkpath"]
                        if b"size" in records and records[b"size"].isdigit():
                            extended["size"] = int(records[b"size"])
                        if any(key.startswith(b"GNU.sparse.") for key in records):
                            extended["sparse"] = True      # a pax sparse member: its typeflag is a plain file, its data is a packed map
                elif kind == "gnu_longname":
                    extended["name"] = cstr(data)
                elif kind == "gnu_longlink":
                    extended["linkname"] = cstr(data)
                continue
            if "name" in extended:
                h["name"] = extended["name"]
            if "size" in extended:
                size_m = extended["size"]
            had_bad_pax = extended.pop("bad", False)
            if extended.get("sparse") and kind in ("file", "other"):
                kind = "sparse"
            extended = {}
            counts["members_read"] += 1
            name = text_of(h["name"])
            withheld_name = shown(name, False) != name
            row = {"member": shown(name), "member_b64": None if withheld_name or nbytes(name) > JUDGE_CHARS else b64(h["name"]), "name_withheld": withheld_name,
                   "type": kind, "size": size_m, "mode": h["mode"], "mtime_raw": h["mtime"], "payload_offset": offset, "source": "tar member of the .ab payload", "parser": PARSER}
            if withheld_name:
                counts["names_withheld"] += 1
            if h["linkname"] and kind in ("symlink", "hardlink"):
                row["link_target_bytes"] = len(h["linkname"])
            kind_n, package, domain, rest, why = classify_name(name)
            state, reason = None, None
            mapped = None
            if had_bad_pax:
                row["pax_header_unreadable"] = True
            if time.monotonic() > deadline:
                clock_stopped = True
            if kind_n == "rejected":
                state, reason = "rejected_name", why
            elif kind in ("sparse",):
                state, reason = "sparse_not_extracted", "a sparse member: its map is not read, so it is listed and not extracted"
            elif kind_n == "other":
                state, reason = "outside_layout", "a member outside apps/ and shared/"
            elif kind_n == "shared":
                state, reason = "shared_storage", "shared storage is not part of the app data layout"
            elif kind_n == "apps" and domain is None:
                state = "directory" if kind == "directory" else "outside_layout"
                reason = "the package directory itself" if kind == "directory" else "a member directly under the package directory"
            elif kind_n == "apps" and domain in NOT_LAID_OUT:
                state, reason = "not_laid_out", NOT_LAID_OUT[domain]
            elif kind_n == "apps" and domain not in DOMAINS:
                state, reason = "unknown_domain", "the domain token is not one of the mapping table or the list of domains that are not laid out"
            elif kind in ("symlink", "hardlink", "character_device", "block_device", "fifo"):
                state, reason = kind, "a %s is listed and never created or followed" % kind.replace("_", " ")
            elif kind == "directory":
                state = "directory"
            elif kind != "file":
                state, reason = "outside_layout", "a member of type %s" % kind
            package_s = shown(package, False) if package is not None else None      # a package named like a recovery password is the placeholder
            package_disp = package if package_s == package else PLACEHOLDER
            if kind_n in ("apps", "manifest") and package is not None:
                row["package"] = package_s
                row["domain"] = shown(domain, False) if domain is not None else None
                if package_s not in package_counts and len(package_counts) < MAX_PACKAGES:
                    package_counts[package_s] = 0
                if package_s in package_counts:
                    package_counts[package_s] += 1
                counts["domains"][domain if domain in DOMAINS or domain in NOT_LAID_OUT or domain == "_manifest" else "(unknown)"] = counts["domains"].get(
                    domain if domain in DOMAINS or domain in NOT_LAID_OUT or domain == "_manifest" else "(unknown)", 0) + 1
            if state is None and wanted is not None and package_s not in wanted:
                state, reason = "not_selected", "the package is not in packages"
            if state is None and kind_n == "manifest":
                if kind != "file":
                    state, reason = "outside_layout", "a _manifest that is not a file"
                else:
                    mapped = ["ab_layout_meta", package_disp, "_manifest"]
            elif state is None:
                root, sub, _what = DOMAINS[domain]
                real_parts = root.split("/") + [package_disp] + ([sub] if sub else []) + list(rest)
                mapped = real_parts
                if not rest:
                    state, reason = "directory", "the domain's own directory"
            if state is None and (clock_stopped):
                state = "not_attempted_max_seconds"
            if state is None and write_stopped:
                state = "not_attempted_write_stopped"
            if state is None:
                shown_rest = shown("/".join(rest), False).split("/") if rest else []
                shown_head = [package] if package else []
                display = list(mapped)
                # withheld components: those of the member's own path are the placeholder, whatever stood there
                if rest and shown_rest != list(rest):
                    tail = len(rest)
                    display[len(display) - tail:] = [PLACEHOLDER if s != r else r for r, s in zip(rest, shown_rest)]
                try:
                    final, notes = tree.resolve(display)
                except TreeFull:
                    state, reason = "layout_full", "the layout holds %d names, the most one run keeps" % MAX_CLAIMS
                else:
                    row["derivative_path"] = "/".join(final)
                    if notes:
                        row["name_collision"] = notes
                        counts["name_collisions"] += 1
                        collisions.append({"member": row["member"], "payload_offset": offset, "derivative_path": row["derivative_path"], "notes": notes})
                    base_name = final[-1]
                    for suffix in SQLITE_SUFFIXES:
                        if base_name.endswith(suffix) and len(base_name) > len(suffix):
                            row["sqlite_companion"] = suffix
                            sqlite_companions.append(hash((tuple(final[:-1]), base_name[:-len(suffix)])))
                            counts["sqlite_companions"] += 1
                    if "sqlite_companion" not in row:
                        sqlite_bases.add(hash((tuple(final[:-1]), base_name)))
            if state is None:
                if not copy_content:
                    state = "planned"
                    if src.skip(size_m) < size_m:
                        state = "not_attempted_max_seconds" if src.error == "the clock" else "truncated_member"
                        reason = "the payload ended inside this member"
                        tar_end = "truncated"
                    else:
                        pad = (-size_m) % 512
                        if src.skip(pad) < pad:
                            tar_end = "truncated"
                else:
                    progress = [0]
                    try:
                        placed, digest = write_member(src, size_m, files_fd, files_path, final, bytes_left, deadline, progress)
                    except Budget as stop:
                        if stop.which == "max_bytes":
                            state, out_of_bytes = "not_extracted_max_bytes", True
                            src.skip(size_m - progress[0])
                        else:
                            state, clock_stopped = "not_attempted_max_seconds", True
                            src.skip(size_m - progress[0])
                        reason = "stopped by %s: no part of the file is in the layout" % stop.which
                    except StreamEnded:
                        state = "not_attempted_max_seconds" if src.error == "the clock" else "truncated_member"
                        reason = "the payload ended inside this member: no part of it is in the layout"
                        tar_end = "truncated"
                    except OSError as exc:
                        state, reason = "write_failed", describe(exc)
                        if getattr(exc, "errno", None) in (errno.ENOSPC, errno.EDQUOT, errno.EFBIG):
                            write_stopped = True
                        src.skip(size_m - progress[0])
                    else:
                        state = "extracted"
                        bytes_left -= size_m
                        counts["extracted_files"] += 1
                        counts["extracted_bytes"] += size_m
                        row["sha256"] = digest
                        if placed.name != final[-1]:
                            row["derivative_path"] = "/".join(final[:-1] + [placed.name])
                            row.setdefault("name_collision", []).append({"kind": "name_taken_on_disk", "component": len(final) - 1})
                            counts["name_collisions"] += 1
                    # the padding after the data
                    if state != "truncated_member":
                        pad = (-size_m) % 512
                        if src.skip(pad) < pad:
                            tar_end = "truncated"
                            if state == "extracted":
                                note("the payload ends in the padding of a member: the member is whole")
            elif kind in ("file", "sparse", "other") or kind not in ("directory", "symlink", "hardlink", "character_device", "block_device", "fifo"):
                # data follows only for these types: skip it
                skipped = src.skip(size_m)
                if skipped < size_m:
                    state = state if state in STATES_PROBLEM else ("not_attempted_max_seconds" if src.error == "the clock" else "truncated_member")
                    tar_end = "truncated"
                else:
                    pad = (-size_m) % 512
                    if src.skip(pad) < pad:
                        tar_end = "truncated"
            if (withheld_name or package_disp != package) and values is not None:
                values.add("member", {"payload_offset": offset}, {"member": name})
            row["state"] = state
            if reason:
                row["reason"] = reason
            counts["states"][state] = counts["states"].get(state, 0) + 1
            result.add(row)
            if tar_end in ("truncated", "damaged"):
                break
        # After the two end blocks: zero padding is fine, anything else is data after the end.
        data_after_end = 0
        if tar_end == "reached":
            while True:
                chunk = src.read(PIECE)
                if not chunk:
                    break
                if any(chunk):
                    data_after_end += sum(1 for b in chunk if b)
        elif tar_end == "missing" and src.state == "reached":
            tar_end = "missing"
    except OutOfTime:
        clock_stopped = True
    if src.error == "the clock":
        clock_stopped = True
        if tar_end in ("missing", "truncated"):
            tar_end = "not_reached"
    sqlite_bases_ok = sum(1 for key in sqlite_companions if key in sqlite_bases)
    counts["sqlite_companions_without_base"] = len(sqlite_companions) - sqlite_bases_ok
    if files_fd is not None:
        os.close(files_fd)
    os.close(fd)
    if values is not None:
        values.close()
    paging = result.finish()

    # --- the answer ----------------------------------------------------------------------------------------------------------------
    stream = src.state if src.state != "reading" else ("reached" if tar_end == "reached" else "not_reached")
    reasons = []
    if stop_reason:
        reasons.append(stop_reason)
    if clock_stopped:
        reasons.append("the time limit stopped the walk")
    if src.state == "not_reached" and src.error == "the decompression budget":
        reasons.append("the decompression budget (%d bytes) ended the payload" % max_decompressed)
    if src.state == "truncated":
        reasons.append("the zlib stream ends before its end marker")
    if src.state == "damaged":
        reasons.append("the zlib stream is damaged (%s)" % scrub(src.error or ""))
    if src.after:
        reasons.append("%d byte(s) follow the end of the zlib stream and are not read" % src.after)
    if tar_end not in ("reached",) and not stop_reason:
        reasons.append("the tar's two end blocks were not reached (%s)" % tar_end)
    if lone_zero:
        reasons.append("%d lone zero block(s) were read past (a header followed them)" % lone_zero)
    if data_after_end:
        reasons.append("data follows the tar's end blocks")
    bad = {k: n for k, n in counts["states"].items() if k in STATES_PROBLEM}
    if bad:
        reasons.append("%d member(s) are not in the layout for a reason that is not by design (%s)" % (sum(bad.values()), ", ".join("%s %d" % kv for kv in sorted(bad.items()))))
    if out_of_bytes:
        reasons.append("max_bytes was reached")
    reasons.extend(problems[:5])
    if not counts["members_read"] and not reasons:
        reasons.append("the payload holds no member")
    complete = not reasons
    by_design = {k: n for k, n in counts["states"].items() if k in ("directory", "not_laid_out", "shared_storage", "symlink", "hardlink", "character_device", "block_device", "fifo", "not_selected")}
    if by_design:
        observations.append("members the tool never extracts, listed with their state: %s" % ", ".join("%s %d" % kv for kv in sorted(by_design.items())))
    if counts["name_collisions"]:
        observations.append("%d member(s) share a name in the layout with another (duplicates, names that differ only in case, a file and a directory): each has its own name and says so in name_collision" % counts["name_collisions"])
    if counts["sqlite_companions_without_base"]:
        observations.append("%d SQLite companion file(s) (-wal, -shm, -journal) have no base file in the same directory of the layout" % counts["sqlite_companions_without_base"])
    if complete:
        status_basis = ("the payload was read to the end of its %s, the tar's two end blocks were found and nothing follows them; every member that is laid out by design was %s"
                        % ("zlib stream" if compressed else "stream (not compressed)", "extracted" if copy_content else "planned (copy_content was false: nothing was extracted)"))
    else:
        status_basis = "partial because " + "; ".join(reasons) + " (see observations and counts)"
    answer = {
        "path": shown(path), "parser": PARSER,
        "status": "complete" if complete else "partial", "status_basis": status_basis,
        "kind": "derivative of an adb backup",
        "derivative_note": "This is a derivative of an adb backup, mapped onto the layout ALEAPP reads. It is not a file-system acquisition of the phone: it holds what the backup agent put in the backup, under the backup's own domains.",
        "copy_content": copy_content,
        "header": header,
        "payload": {"stream": stream, "tar_end": tar_end, "bytes_decompressed": src.produced, "budget": max_decompressed, "bytes_after_stream": src.after,
                    "lone_zero_blocks": lone_zero, "bytes_after_tar_end": data_after_end},
        "mapping": {t: {"to": "%s/<package>%s" % (root, "/" + sub if sub else ""), "is": what} for t, (root, sub, what) in DOMAINS.items()},
        "not_laid_out_domains": NOT_LAID_OUT,
        "limits": {"max_members": max_members, "max_bytes": max_bytes, "max_decompressed_bytes": max_decompressed, "max_seconds": max_seconds},
        "derivative": ({"root": shown_base + "/ab_layout/derivative", "banner": shown_base + "/ab_layout/derivative/DERIVATIVE.json",
                        "values_file": values.shown, "values_written": values.written} if copy_content else
                       {"written": False, "note": "copy_content was false: nothing was extracted and no derivative was made; the result file is the plan"}),
        "counts": counts, "packages": dict(sorted(package_counts.items())[:limit]), "package_count": len(package_counts),
        "observations": observations, "problems": problems,
        "entries": result.page, "entry_count": result.rows,
        "collisions": collisions[:limit], "collision_count": len(collisions), "collisions_in": paging["all_results"] if collisions else None,
        "pages": {"entries": paging}, "truncated": paging["truncated"] or len(collisions) > limit or len(package_counts) > limit,
        "paths_withheld": PATHS_WITHHELD[0],
        "note": "Each row is one member of the backup's tar, with the name as spelled (member, and member_b64 for the exact bytes, null for a withheld name), its offset in the "
                "decompressed payload, its size, type, mode and raw time. Cite the member name and the offset with the backup it came from.",
    }
    CLEANUP.clear()
    send(answer)


BANNER = {"kind": "derivative of an adb backup", "tool": TOOL, "parser": PARSER,
          "is_not": "a file-system acquisition of the phone; it holds only what the backup agent put in the backup",
          "layout": "data/data/<package>/{files,databases,shared_prefs,no_backup,cache}/... and data/user_de/0/<package>/... from the FullBackup domains; "
                    "ab_layout_meta/<package>/_manifest is the package's manifest record"}


def _code(stop):
    return stop.code if isinstance(stop.code, int) else (0 if stop.code is None else 1)


def _leave(code):
    """End the call at once, after the answer is out. The interpreter's own teardown resets the signal handlers to their defaults before it frees
    what the call held, and a stop signal that lands there kills the process by its default action (exit null, not 128 + the signal) with a whole
    answer already printed. What the interpreter would have run at its end (the atexit hooks that remove a temporary file) is run here, with the
    handlers still in; a signal before this point is answered by the handlers as before."""
    try:
        sys.stdout.flush()
    except SystemExit as stop:
        code = _code(stop)
    except Exception:  # noqa: BLE001 - a reader that is gone: the exit code is the one the call had
        pass
    try:
        sys.stderr.flush()
    except Exception:  # noqa: BLE001
        pass
    try:
        import atexit as _atexit
        _atexit._run_exitfuncs()
    except Exception:  # noqa: BLE001 - a hook that fails is not a failure of the answer
        pass
    os._exit(code)


if __name__ == "__main__":
    exit_code = 0
    try:
        run_main(main)
    except SystemExit as stop:
        exit_code = _code(stop)
    _leave(exit_code)
