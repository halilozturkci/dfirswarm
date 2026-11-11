#!/usr/bin/env python3
"""Measure how tightly a series of event times clusters around its median interval.

That is all this measures. It reports the median interval, the median absolute
deviation (MAD) and the MAD as a fraction of the median, a density ratio, and
the longest stretch at the end of the series. A series that clusters tightly is
regular; regular is not malicious (update checks, telemetry, NTP, revocation
checks and monitoring agents are all more regular than most malware), and an
irregular series says nothing about a destination either. The shape names
describe dispersion, with fixed cut-offs that are conventions of this tool, not
properties of any implant. A score is a measurement to be set against comparable
hosts and services, not a verdict.

What a result can and cannot say:

  - The series is what the caller supplied. A time with no zone is refused unless
    the caller says to read it as UTC (assume_utc), and every such value is
    counted. A value that is not a finite number of seconds, or is not epoch
    seconds at all (a millisecond count), is counted and named, never scored.
  - Duplicate times are counted apart from distinct events; the minimum event
    count applies to the distinct ones.
  - long_final_gap is an observation: the last interval is more than four times
    the median, and it ENDS IN AN OBSERVED EVENT, so the series resumed. It is
    not a cessation. Whether anything stopped needs a declared observation
    window (window_end) and a statement that the sensor kept recording over it
    (sensor_coverage_confirmed); only then is the silence after the last event
    stated, as a bounded negative about this series alone.
  - event_density_ratio is the distinct events divided by the count a constant
    schedule at the median interval would give over the same span. Below 1 it
    means fewer events than that schedule, for any reason (pauses, jitter, a
    series that is not periodic, missing records); it does not establish that
    events are missing.
  - The whole interval list is kept: inline a bounded page, the rest in a file
    the answer names (and intervals.tsv in out_dir when one is given).
"""

# BEGIN SHARED ENDS
# The same text is in every pack tool and recipe and in their tool-library twins, before the file's own imports (tests/shared-blocks-census.test.ts
# holds the copies equal): the two ends of a call, where a stop signal (SIGTERM, SIGINT, SIGHUP) found no handler, or one that did harm.
# * The start. From here a stop is answered by ONE JSON document and exit 128 + the signal, until the tool installs its own handlers (which then
#   answer it), and for good for a signal the tool never takes. Only the start of the interpreter and the compiling of the file come before
#   it: a stop there ends the process with no answer, before anything was read. answer_a_stop() is that document: a handler whose own last word
#   wrote nothing on standard output calls it before it ends the process, so that a stop is never answered by silence.
# * The end. The interpreter's own teardown resets the handlers to their defaults before it frees what the call held, and a stop that landed
#   there killed a process that had printed its whole answer; a handler that raises, writes a last word or ends the process, run once the
#   answer was decided, wrote a second document, a traceback, or nothing at all. Python runs a handler on the main thread whichever thread the
#   signal reached, so a mask of the main thread alone holds nothing while another thread runs. hold_stop_signals() holds the stop signals for
#   good: blocked in this thread and given a handler that does nothing, which is the hold whatever thread the signal reaches; an error Python
#   can only report from then on (a file left open whose last write the file system refuses, closed when the frame that held it is freed) is
#   not printed (3.11 and 3.12 say nothing of it, 3.14 a traceback). A handler that was due runs on the way in: what it raises reaches the
#   writer that asked (the tool's own handling then answers the stop, before any byte of the answer), or, quietly, is dropped (the end of a
#   call, an error branch). Every writer of a final answer calls it before it commits to writing, every error branch at the end calls it
#   quietly, and, when the file runs as a program, standard output is wrapped so that its first write calls it too. _code(stop) is a
#   SystemExit's exit code (its text, if it has one, goes to standard error as the interpreter puts it), and _leave(code) ends the call: both
#   hold the signals first, quietly; _leave flushes
#   standard output (a write that fails there makes a 0 an exit 120, as the interpreter does) and standard error, runs the atexit hooks (a hook
#   that removes a temporary file), each step on its own and none able to raise, and ends the process with os._exit, never through the teardown.
# The modules are imported here, as the file is loaded, never inside the ending (an import there ran a due handler inside the import system).
import atexit
import json
import os
import signal
import sys

_ENDING = {"held": False, "program": __name__ == "__main__"}      # imported (a test that loads the file as a module), the block holds nothing
_ENDING_SIGNALS = (signal.SIGTERM, signal.SIGINT, signal.SIGHUP)


def answer_a_stop(signum, when="before it had answered"):
    """The one document of a stop that ends the call before any answer was begun (nothing once one has): status failed, interrupted, and
    no claim about what was read or written. A handler whose own last word printed nothing calls it before it ends the process. It writes
    only when the file runs as a program: its wrapped standard output is what knows whether an answer was begun."""
    if _ENDING["held"] or not isinstance(sys.stdout, _AnswerStream):
        return
    _ENDING["held"] = True
    name = {signal.SIGTERM: "SIGTERM", signal.SIGINT: "SIGINT", signal.SIGHUP: "SIGHUP"}.get(signum, "signal %d" % signum)
    text = json.dumps({"error": "the tool was stopped by %s %s" % (name, when), "status": "failed", "interrupted": name,
                       "status_basis": "stopped by %s %s: no answer was made, and what it had read or written by then is not described" % (name, when)})
    try:
        os.write(1, (text + "\n").encode("ascii"))
    except OSError:
        pass


def _stopped_without_handler(signum, _frame):
    for other in _ENDING_SIGNALS:
        try:
            signal.signal(other, signal.SIG_IGN)
        except (ValueError, OSError):
            pass
    answer_a_stop(signum, "while it was being loaded, or at a point where it has no stop handling of its own")
    os._exit(128 + signum)


def _ending_nothing(*_ignored):
    """The stop signals' handler, and sys.unraisablehook, once the answer has begun: nothing."""


def hold_stop_signals(quietly=False):
    """Hold the stop signals for good. A handler that was due runs on the way in, before the hold and before any byte of the answer, and what
    it raises is raised here, so that the tool's own handling of a stop answers it; quietly (the end of a call, an error branch, where nothing
    may escape) it is dropped and the hold is made all the same. Called by a thread that is not the main one, it blocks the signals there and
    leaves the rest to the main thread's next call."""
    for _attempt in range(len(_ENDING_SIGNALS) + 2):
        if _ENDING["held"] or not _ENDING["program"]:
            return
        try:
            try:
                signal.pthread_sigmask(signal.SIG_BLOCK, _ENDING_SIGNALS)
            except (AttributeError, ValueError, OSError):
                pass                  # no pthread_sigmask here: the handler below is the hold
            main_thread = True
            for signum in _ENDING_SIGNALS:
                try:
                    signal.signal(signum, _ending_nothing)
                except (ValueError, OSError):
                    main_thread = False
            sys.unraisablehook = _ending_nothing
            _ENDING["held"] = main_thread
            return
        except BaseException:  # noqa: BLE001 - a handler that was due ran on the way in, and raised
            if not quietly:
                raise



class _AnswerStream:
    """Standard output of a call: the first write holds the stop signals (above); everything else is the stream's own."""

    def __init__(self, stream):
        self._stream = stream

    def write(self, text):
        if not _ENDING["held"]:
            hold_stop_signals()
        return self._stream.write(text)

    def writelines(self, lines):
        if not _ENDING["held"]:
            hold_stop_signals()
        return self._stream.writelines(lines)

    def __getattr__(self, name):
        if name == "_stream":
            raise AttributeError(name)
        return getattr(self._stream, name)


def _code(stop):
    hold_stop_signals(quietly=True)
    code = getattr(stop, "code", 1)
    if isinstance(code, int):
        return code
    if code is not None:
        try:
            sys.stderr.write("%s\n" % (code,))
        except BaseException:  # noqa: BLE001
            pass
    return 0 if code is None else 1


def _leave(code):
    hold_stop_signals(quietly=True)
    code = code if isinstance(code, int) else 1
    try:
        sys.stdout.flush()
    except BaseException:  # noqa: BLE001 - a reader that is gone: the answer did not reach it
        code = code or 120
    try:
        sys.stderr.flush()
    except BaseException:  # noqa: BLE001
        pass
    try:
        atexit._run_exitfuncs()
    except BaseException:  # noqa: BLE001 - a hook that fails is not a failure of the answer
        pass
    os._exit(code)


if __name__ == "__main__":
    if sys.stdout is not None and not isinstance(sys.stdout, _AnswerStream):
        sys.stdout = _AnswerStream(sys.stdout)
    for _signum in _ENDING_SIGNALS:
        signal.signal(_signum, _stopped_without_handler)
# END SHARED ENDS


import json
import os
import signal
import sys

TOOL = {"name": "beacon_score", "version": 10}


def _before_start(signum, _frame):
    """A stop that arrives while the rest of this file is still loading (the other imports, the compile of what follows): the first signal
    counts, nothing was read, started or written, and the one answer says so. main() installs the tool's own handlers and replaces this one.
    What no script can answer is a stop that arrives before the interpreter has run these first lines (its own start-up)."""
    for other in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(other, signal.SIG_IGN)
    try:
        sys.stdout.write(json.dumps({"tool": TOOL, "status": "partial", "ok": False, "stage": "starting",
                                     "status_basis": "stopped by signal %d before any work: nothing was read, started or written" % signum,
                                     "interrupted_by_signal": signum}) + "\n")
        sys.stdout.flush()
    except (OSError, ValueError):
        pass
    os._exit(128 + signum)


for _signum in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
    signal.signal(_signum, _before_start)   # replaced by main() once the module is loaded


import array
import datetime
import errno
import math
import re
import secrets
import select
import stat
import tempfile
import time
from pathlib import Path

MAX_EPOCH = 4_102_444_800        # 2100-01-01: a number above it is not epoch seconds (milliseconds, microseconds, nanoseconds)
MAX_EVENTS = 3_000_000          # measured: 336 MB resident at this many events (it was 1.19 GB for the same 3 million before the series was packed)
MAX_INLINE_EVENTS = 500_000     # a series passed in `timestamps`: the arguments are parsed whole (about 50 MB resident at this many), so a longer one belongs in timestamps_file
MAX_ARGUMENT_BYTES = 32 << 20   # the arguments are read up to this many bytes; more is refused before it is parsed
ARGUMENT_COMMA_SLACK = 4096     # the commas the arguments may hold beyond one for each of MAX_INLINE_EVENTS events (the other parameters, a label, a path)
ARGUMENT_READ_SECONDS = 45      # stdin must be closed by then (the manifest's limit is 60); BEACON_SCORE_ARGUMENT_SECONDS shortens it for the tests
DEFAULT_LIMIT = 40
MAX_VALUE_CHARS = 4096          # a longer line of a timestamps_file is not a time
DEFAULT_SECONDS = 40            # the tool's own clock for reading; the manifest's limit is 60 seconds
MAX_SECONDS = 45
TAIL_PER_READ = 1.5             # the ordering and the measurement after the last value take 0.6 (sorted) to 0.93 (shuffled) times as long as reading did at full speed, and about 1.4 times with a tenth of a CPU
EXTRA_FOR_LIST = 0              # seconds past that clock the interval list may still take: none, reading and measuring have used their share and the answer needs room before 60


def describe(exc):
    return "%s: %s" % (type(exc).__name__, getattr(exc, "strerror", None) or str(exc))


def holds_files(directory):
    """Whether `directory` holds anything: one entry is looked at, never the whole listing (a caller's directory can hold millions of names)."""
    with os.scandir(directory) as entries:
        return next(entries, None) is not None


class signals_held:
    """The stop signals wait, pending, while a hidden temporary file is made and registered for removal: a signal that arrives between
    the two would run the clean-up before it knew of the file, and the process would leave with the file behind. Where the platform cannot
    hold signals the registration still follows at once, so only the file's own creation is unprotected."""

    def __enter__(self):
        self.before = None
        if hasattr(signal, "pthread_sigmask"):
            self.before = signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGTERM, signal.SIGINT, signal.SIGHUP})
        return self

    def __exit__(self, *_exc):
        if self.before is not None:
            signal.pthread_sigmask(signal.SIG_SETMASK, self.before)
        return False


_TEMPS = set()      # the hidden .<name>-* files of the paging objects that are not yet under their final names


def drop_temps():
    """A refused, failed, signalled or write-failed run leaves no hidden partial file in tool-output: only a finished file is moved to its name."""
    for path in list(_TEMPS):
        try:
            os.unlink(path)
        except OSError:
            pass
        _TEMPS.discard(path)


def fail(message, **extra):
    hold_stop_signals()
    if hasattr(signal, "pthread_sigmask"):
        signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGTERM, signal.SIGINT, signal.SIGHUP})     # one document: a stop that arrives while this is written waits, and the tool leaves with it
    drop_temps()
    print(json.dumps({"error": message, "tool": TOOL, "status": "failed", "status_basis": "the tool stopped with an error (see error)", **extra}))
    raise SystemExit(1)


def in_job():
    return bool(os.environ.get("JOB_ID") and os.environ.get("OUT"))


def refuse_followed_page_dir():
    """The whole results of a long list are written under tool-output (in a job, $OUT/tool-output). If that name is already a symbolic link
    the results would land where it points, outside the place the tool is allowed to write: refuse before anything is read."""
    job, out = os.environ.get("JOB_ID"), os.environ.get("OUT")
    if job and out:
        directory = os.path.join(out, "tool-output")
    else:
        directory = os.path.join("work", re.sub(r"[^A-Za-z0-9_.-]", "_", os.environ.get("AGENT_ID") or "tool"), "tool-output")
    if os.path.islink(directory):
        fail("tool-output is a symbolic link: the whole results would be written where it points. Remove it, or give the run a directory of its own", tool_output=directory)


def resolve_output(out, what="output"):
    """Where `out` really lands, as a path under the run directory; a place
    outside it, the run directory itself, or anything under inputs/ is refused.
    In a job it is a directory under $OUT, the one place a job writes."""
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


# Lossless paging (the same in every pack tool that pages); see pcap_summary.
class LosslessPage:
    def __init__(self, tool, limit):
        if isinstance(limit, bool) or not isinstance(limit, int) or limit < 1:
            raise ValueError("limit must be a positive integer")
        self.tool = re.sub(r"[^A-Za-z0-9_.-]", "_", tool)
        self.limit = limit
        self.page = []
        self.total = 0
        self._out = None
        self._tmp = None
        name = "%s-%s.jsonl" % (self.tool, secrets.token_hex(8))
        job, out = os.environ.get("JOB_ID"), os.environ.get("OUT")
        if job and out:
            self.path = Path(out) / "tool-output" / name
            self.shown = "store/jobs/%s/out/tool-output/%s" % (re.sub(r"[^A-Za-z0-9_.-]", "_", job), name)
        else:
            agent = re.sub(r"[^A-Za-z0-9_.-]", "_", os.environ.get("AGENT_ID") or "tool")
            self.path = Path("work") / agent / "tool-output" / name
            self.shown = str(self.path)

    def _abandon(self):
        """The file cannot be finished (a full disk, a size limit, a failed move): close it and remove it, so no hidden partial file stays."""
        try:
            if self._out is not None:
                self._out.close()
        except OSError:
            pass
        if self._tmp is not None:
            _TEMPS.discard(str(self._tmp))
            try:
                os.unlink(self._tmp)
            except OSError:
                pass

    def _write(self, row):
        try:
            self._out.write(json.dumps(row, ensure_ascii=True, default=str))
            self._out.write("\n")
        except OSError:
            self._abandon()
            raise

    def add(self, row):
        self.total += 1
        if len(self.page) < self.limit:
            self.page.append(row)
            return
        if self._out is None:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with signals_held():
                fd, name = tempfile.mkstemp(dir=self.path.parent, prefix=".%s-" % self.path.name)
                self._tmp = Path(name)
                _TEMPS.add(name)          # known to the clean-up from the moment it exists
            self._out = os.fdopen(fd, "w", encoding="utf-8")
            for kept in self.page:
                self._write(kept)
        self._write(row)

    def finish(self):
        result = {"matched": self.total, "returned": len(self.page), "truncated": self.total > len(self.page)}
        if self._out is not None:
            try:
                self._out.flush()
                os.fsync(self._out.fileno())
                self._out.close()
                os.replace(self._tmp, self.path)
            except OSError:
                self._abandon()
                raise
            _TEMPS.discard(str(self._tmp))
            result["all_results"] = self.shown
            result["all_results_format"] = "JSON Lines, one complete result per line"
        return result


ISO_TIME = re.compile(r"(\d{4})-(\d{2})-(\d{2})(?:[T ](\d{2}):(\d{2})(?::(\d{2})(?:\.(\d{1,9}))?)?)?[ ]?(Z|z|[+-]\d{2}(?::?\d{2})?)?")


def iso_seconds(text):
    """ISO 8601 text as (seconds since the epoch, has a zone) or None. Written by hand, because the standard library's
    fromisoformat accepts different forms in different Python versions (hour 24, a bare fraction point, ...), and a series
    must read the same on every interpreter the tool runs on. The forms: YYYY-MM-DD, with `T` or one space and HH:MM or
    HH:MM:SS and up to nine fraction digits, then Z or +hh, +hh:mm, +hhmm. Hour 24 and second 60 are not accepted."""
    m = ISO_TIME.fullmatch(text)
    if not m:
        return None
    year, mon, day, hh, mm, ss, frac, zone = m.groups()
    try:
        stamp = datetime.datetime(int(year), int(mon), int(day), int(hh or 0), int(mm or 0), int(ss or 0), tzinfo=datetime.timezone.utc)
    except ValueError:
        return None
    seconds = (stamp - datetime.datetime(1970, 1, 1, tzinfo=datetime.timezone.utc)).total_seconds()
    if frac:
        seconds += int(frac) / 10 ** len(frac)
    if zone and zone not in ("Z", "z"):
        digits = zone[1:].replace(":", "")
        offset = int(digits[:2]) * 3600 + int(digits[2:] or 0) * 60
        if int(digits[:2]) > 23 or int(digits[2:] or 0) > 59:
            return None
        seconds -= offset if zone[0] == "+" else -offset
    return seconds, zone is not None


def read_time(value, assume_utc):
    """(seconds since the epoch, None) or (None, reason). A reason is one of unparseable, non_finite, out_of_range,
    naive: nothing is guessed, and a number is epoch seconds."""
    if isinstance(value, bool) or value is None:
        return None, "unparseable"
    if isinstance(value, (int, float)):
        try:
            number = float(value)
        except OverflowError:
            return None, "out_of_range"      # an integer too large for a float is a number, and not epoch seconds
    elif isinstance(value, str):
        text = value.strip()
        try:
            number = float(text)
        except ValueError:
            number = None
        except OverflowError:
            return None, "out_of_range"
        if number is None:
            read = iso_seconds(text)
            if read is None:
                return None, "unparseable"
            number, has_zone = read
            if not has_zone:
                if not assume_utc:
                    return None, "naive"
                if not math.isfinite(number):
                    return None, "non_finite"
                return number, "assumed_utc"
    else:
        return None, "unparseable"
    if not math.isfinite(number):
        return None, "non_finite"
    if number < 0 or number > MAX_EPOCH:
        return None, "out_of_range"
    return number, None


def sealed_path(path):
    """In a job, where a file under $OUT is cited once the job is sealed; otherwise the path as it is."""
    job, out = os.environ.get("JOB_ID"), os.environ.get("OUT")
    if not path or not (job and out):
        return path
    try:
        rel = Path(path).resolve().relative_to(Path(out).resolve())
    except ValueError:
        return path
    return "store/jobs/%s/out/%s" % (re.sub(r"[^A-Za-z0-9_.-]", "_", job), rel)


def iso(stamp):
    try:
        return datetime.datetime.fromtimestamp(stamp, datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    except (OverflowError, OSError, ValueError):
        return None


def shape_of(relative):
    if relative is None:
        return "unmeasurable"
    if relative <= 0.02:
        return "tight_cluster"
    if relative <= 0.25:
        return "clustered"
    if relative <= 0.6:
        return "loose_cluster"
    return "dispersed"


class Stopped(BaseException):
    """SIGTERM, SIGINT or SIGHUP, raised in the main thread by the handler (a handler that did the work of answering could be
    running in the middle of what it reports)."""

    def __init__(self, signum):
        super().__init__(signum)
        self.signum = signum


def _stop(signum, _frame):
    if ANSWERING[0]:
        return     # the answer is out or being written: it is the one document, and the call ends with it
    for other in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(other, signal.SIG_IGN)     # the first signal counts: a second one starts no second answer
    raise Stopped(signum)


PROGRESS = {"stage": "arguments", "values_read": 0}      # what the last word says


def check_label(label):
    """A label is a few plain words: it is printed back. Printable ASCII up to 80 characters, and no run of more than 15 letters,
    digits, underscores, hyphens, plus signs, slashes or equals signs without a break (a space, a dot, a colon, a bracket or any
    other mark): a token, a key or a base64 text has such a run, a description does not."""
    if label is None:
        return None
    if (not isinstance(label, str) or not re.fullmatch(r"[\x20-\x7e]{1,80}", label)
            or any(len(run) > 15 for run in re.findall(r"[A-Za-z0-9_+/=-]+", label))):
        fail("label must be a few plain words: up to 80 printable ASCII characters with no run of more than 15 letters, digits or _ + / = - "
             "without a break (it is printed back in the answer)")
    return label


class ReadTimeUp(Exception):
    """The clock ran out inside a line too long to be a time: the rest of it is not read."""

    def __init__(self, index):
        super().__init__(index)
        self.index = index


def length_of(value):
    """The length of a value's text as the series gave it, for the record of a value that was not scored; None when it has none
    (null) or when the text of a structure nested too deep to be written is not built (a list nested 100,000 deep overflows the
    stack on Python 3.14)."""
    if value is None:
        return None
    try:
        return len(str(value))
    except RecursionError:
        return None


def values_of(file_arg, raw, counters, deadline=None):
    """The series as (input position, value) pairs, one at a time: a file is read line by line and never held. A line too long to
    be a time is counted and yields None; a blank line and a comment are not positions. A line the rest of which is skipped is
    skipped under the clock (`deadline`): a file with no line break in it is as long as the disk."""
    if file_arg is not None:
        # opened without blocking and looked at once: a name that became a pipe since main() checked it is refused, never waited on for a writer
        fd = os.open(file_arg, os.O_RDONLY | os.O_NONBLOCK)
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                raise OSError(errno.EINVAL, "not a regular file")
            source = os.fdopen(fd, "r", encoding="utf-8", errors="replace")
        except BaseException:
            os.close(fd)
            raise
        with source as fh:
            index = 0
            while True:
                line = fh.readline(MAX_VALUE_CHARS + 1)
                if not line:
                    return
                if len(line) > MAX_VALUE_CHARS and not line.endswith("\n"):
                    while line and not line.endswith("\n"):
                        line = fh.readline(MAX_VALUE_CHARS)
                        if deadline is not None and time.monotonic() > deadline:
                            raise ReadTimeUp(index)
                    counters["long_lines"] += 1
                    yield index, None
                    index += 1
                    continue
                text = line.strip()
                if not text or text.startswith("#"):
                    continue
                yield index, text
                index += 1
    else:
        yield from enumerate(raw)


def median_of(values):
    ordered = sorted(values)
    n = len(ordered)
    if n % 2:
        return ordered[n // 2]
    return (ordered[n // 2 - 1] + ordered[n // 2]) / 2


def read_arguments(began):
    """stdin up to MAX_ARGUMENT_BYTES + 1 bytes, until it is closed, under the tool's clock: a writer that never closes it ends the call as JSON at
    ARGUMENT_READ_SECONDS, not at the harness's kill. A stop signal ends the wait at once (the handler raises)."""
    try:
        limit = float(os.environ["BEACON_SCORE_ARGUMENT_SECONDS"])
    except (KeyError, ValueError):
        limit = ARGUMENT_READ_SECONDS
    try:
        fd = sys.stdin.fileno()
    except (AttributeError, ValueError, OSError) as exc:
        fail("the arguments cannot be read: there is no standard input (%s)" % describe(exc))
    chunks, total = [], 0
    while total <= MAX_ARGUMENT_BYTES:
        wait = began + limit - time.monotonic()
        if wait <= 0:
            fail("the arguments did not arrive within %g seconds: standard input was not closed by the writer" % limit)
        try:
            ready, _, _ = select.select([fd], [], [], min(wait, 1.0))
            chunk = os.read(fd, min(1 << 20, MAX_ARGUMENT_BYTES + 1 - total)) if ready else None
        except OSError as exc:
            fail("the arguments could not be read (%s)" % describe(exc))
        if chunk is None:
            continue
        if not chunk:
            break
        chunks.append(chunk)
        total += len(chunk)
    return b"".join(chunks)


def main():
    began = time.monotonic()         # the clock starts here: reading the arguments is part of what max_seconds covers
    for signum in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(signum, _stop)
    given = read_arguments(began)
    if len(given) > MAX_ARGUMENT_BYTES:
        # the rest is read and dropped (for a few seconds at most), so that the caller writing it is not left with a broken pipe instead of the answer
        drain_until = time.monotonic() + 5
        while time.monotonic() < drain_until and sys.stdin.buffer.read(1 << 20):
            pass
        fail("the arguments are larger than %d MiB: give the series as timestamps_file (one time per line, up to %d events), not inline" % (MAX_ARGUMENT_BYTES >> 20, MAX_EVENTS))
    commas = given.count(b",")
    if commas > MAX_INLINE_EVENTS + ARGUMENT_COMMA_SLACK:
        # a list of MAX_INLINE_EVENTS events has that many commas less one, in any nesting: more than that cannot be an inline series within the cap, and is
        # refused before the parse builds a Python object for each of up to 32 MiB of one-byte elements (428 MB resident for 32 MiB of 0.5,)
        fail("the arguments hold %d commas, more than a series of at most %d events passed inline can: give the series as timestamps_file (one time per line, up to %d events)"
             % (commas, MAX_INLINE_EVENTS, MAX_EVENTS))
    try:
        args = json.loads(given)
    except (ValueError, RecursionError) as exc:
        fail("arguments are not valid JSON", reason=str(exc))
    del given
    if not isinstance(args, dict):
        fail("arguments must be a JSON object")
    raw, file_arg = args.get("timestamps"), args.get("timestamps_file")
    if raw is not None and file_arg is not None:
        fail("give one of timestamps or timestamps_file, not both")
    if raw is None and file_arg is None:
        fail("timestamps is required: a list of event times, epoch seconds or ISO 8601 with a zone (or timestamps_file, one per line)")
    minimum = args.get("min_events", 6)
    if isinstance(minimum, bool) or not isinstance(minimum, int) or minimum < 3:
        fail("min_events must be an integer of at least 3")
    limit = args.get("limit", DEFAULT_LIMIT)
    if isinstance(limit, bool) or not isinstance(limit, int) or limit < 1:
        fail("limit must be a positive integer")
    assume_utc = args.get("assume_utc", False)
    confirmed = args.get("sensor_coverage_confirmed", False)
    for key, value in (("assume_utc", assume_utc), ("sensor_coverage_confirmed", confirmed)):
        if not isinstance(value, bool):
            fail("%s must be true or false" % key)
    label = check_label(args.get("label"))
    seconds_allowed = args.get("max_seconds", DEFAULT_SECONDS)
    if isinstance(seconds_allowed, bool) or not isinstance(seconds_allowed, (int, float)) or not 1 <= seconds_allowed <= MAX_SECONDS:
        fail("max_seconds must be a number from 1 to %d: the tool stops reading and answers with what it has before the manifest's 60-second limit" % MAX_SECONDS)
    deadline = began + seconds_allowed
    # max_seconds is the budget for reading AND measuring: the part after the last value cannot be interrupted and takes about as long as the
    # reading did, so reading stops when it has used its share. A slow CPU then still ends with a partial answer inside the manifest's limit.
    read_deadline = began + seconds_allowed / (1 + TAIL_PER_READ)
    out_dir = args.get("out_dir")
    if out_dir is not None:
        if not isinstance(out_dir, str) or not out_dir:
            fail("out_dir must be a non-empty string")
        out_dir = resolve_output(out_dir, "out_dir")
        try:
            if os.path.exists(out_dir) and holds_files(out_dir):
                fail("out_dir already holds files", out_dir=out_dir)
        except OSError as exc:
            fail("out_dir cannot be listed (%s)" % describe(exc), out_dir=out_dir)
    if file_arg is not None:
        if not isinstance(file_arg, str) or not file_arg:
            fail("timestamps_file must be a path")
        if not os.path.isfile(file_arg):
            # /dev/zero, a pipe or a directory is not a series: opening one would block, or never end
            fail("timestamps_file must name a regular file", timestamps_file=file_arg)
    else:
        if not isinstance(raw, list) or not raw:
            fail("timestamps is required: a non-empty list of event times, epoch seconds or ISO 8601 with a zone")
        if len(raw) > MAX_INLINE_EVENTS:
            fail("timestamps holds %d events, more than the %d a series passed inline may have: give it as timestamps_file (one time per line, up to %d events)"
                 % (len(raw), MAX_INLINE_EVENTS, MAX_EVENTS))

    refuse_followed_page_dir()
    PROGRESS["stage"] = "reading the series"
    counters = {"long_lines": 0}
    # The series is parsed once, as it is read: seconds in a packed array (8 bytes an event), the position of each in the input
    # in another (4 bytes), and whether the input is already in time order, so that the common case needs no sort at all.
    secs, positions = array.array("d"), array.array("I")
    rejected = {"unparseable": 0, "non_finite": 0, "out_of_range": 0}
    # Positions, reasons and lengths of every value that was not scored: five inline, all of them in a file the answer names.
    rejected_page, naive_page = LosslessPage("beacon_rejected", 5), LosslessPage("beacon_without_zone", 5)
    naive, assumed = 0, 0
    supplied, in_order, previous = 0, True, None
    timed_out_at = None
    try:
        for index, value in values_of(file_arg, raw, counters, read_deadline):
            supplied += 1
            if supplied > MAX_EVENTS:
                fail("the series has more than %d events: split it by destination or by window" % MAX_EVENTS, **({"timestamps_file": file_arg} if file_arg else {}))
            PROGRESS["values_read"] = supplied
            if supplied & 4095 == 0 and time.monotonic() > read_deadline:
                timed_out_at = index
                supplied -= 1
                break
            seconds, reason = read_time(value, assume_utc)
            if reason == "naive":
                naive += 1
                naive_page.add({"index": index, "length": len(str(value))})
                continue
            if reason == "assumed_utc":
                assumed += 1
            elif reason:
                rejected[reason] += 1
                rejected_page.add({"index": index, "reason": reason, "length": length_of(value)})
                continue
            seconds = round(seconds, 6)
            if previous is not None and seconds < previous:
                in_order = False
            previous = seconds
            secs.append(seconds)
            positions.append(index)
    except ReadTimeUp as up:
        timed_out_at = up.index
    except OSError as exc:
        fail("timestamps_file could not be read (%s)" % describe(exc), timestamps_file=file_arg)
    except Stopped:
        raise
    if naive:
        shown_naive = naive_page.finish()
        fail("%d of the times carry no time zone; a series that is not UTC cannot be read as UTC without being told to. Give the zone in each time "
             "(Z or +hh:mm), or pass assume_utc: true if the source is known to be UTC" % naive,
             timestamps_without_zone=naive, first_without_zone=naive_page.page, all_without_zone=shown_naive.get("all_results"))

    window_end = None
    if args.get("window_end") is not None:
        window_end, why = read_time(args["window_end"], assume_utc)
        if window_end is None:
            fail("window_end could not be read as a time (%s): epoch seconds or ISO 8601 with a zone" % why,
                 window_end_length=length_of(args["window_end"]))

    PROGRESS["stage"] = "ordering the series"
    count = len(secs)
    order = None if in_order else sorted(range(count), key=secs.__getitem__)
    distinct, first_at = array.array("d"), array.array("I")        # the distinct times, and the input position of the first of each
    for p in (range(count) if order is None else order):
        s = secs[p]
        if distinct and distinct[-1] == s:
            continue
        distinct.append(s)
        first_at.append(positions[p])
    del order
    rejected_pages = rejected_page.finish()
    first_rejected = rejected_page.page
    if len(distinct) < minimum:
        fail("too few distinct usable times to score", usable=count, distinct_events=len(distinct), needed=minimum,
             rejected=rejected, first_rejected=first_rejected, all_rejected=rejected_pages.get("all_results"),
             note="A handful of distinct events cannot show periodicity, and scoring them would invent a pattern. Identical times count once.")
    if window_end is not None and window_end < distinct[-1]:
        fail("window_end is earlier than the last event: the window cannot end before the series does",
             window_end=iso(window_end), last_event=iso(distinct[-1]))

    PROGRESS["stage"] = "measuring the intervals"
    intervals = array.array("d", (round(b - a, 6) for a, b in zip(distinct, distinct[1:])))
    median = median_of(intervals)
    mad = median_of(abs(i - median) for i in intervals)
    relative = (mad / median) if median else None
    span = distinct[-1] - distinct[0]
    expected = (span / median + 1) if median else None
    density = (len(distinct) / expected) if expected else None

    final_gap = {"present": False}
    if len(intervals) >= 3 and median and intervals[-1] > median * 4:
        final_gap = {"present": True, "from": iso(distinct[-2]), "to": iso(distinct[-1]),
                     "final_interval_seconds": intervals[-1], "median_interval_seconds": round(median, 6),
                     "ratio": round(intervals[-1] / median, 3), "threshold": "more than four times the median interval",
                     "meaning": "The last interval is long and ends in an observed event: the series resumed, or was only sparsely observed in that "
                                "stretch. It is an observation about the series, not a cessation, and no time of any stopping follows from it."}

    cessation = {"assessed": False}
    if window_end is None:
        cessation["reason_not_assessed"] = ("no observation window was declared. Whether anything stopped is a statement about the time after the last "
                                            "event, and it needs window_end (when the sensor's coverage of this series ends) and "
                                            "sensor_coverage_confirmed")
    elif not confirmed:
        cessation["reason_not_assessed"] = ("a window_end was declared without sensor_coverage_confirmed: silence after the last event means nothing "
                                            "unless the sensor was recording over it, and this tool cannot tell")
        cessation["declared_window_end"] = iso(window_end)
    else:
        silent = round(window_end - distinct[-1], 6)
        over = bool(median) and silent > median * 4
        cessation = {"assessed": True, "declared_window_end": iso(window_end), "sensor_coverage_confirmed": True,
                     "silent_after_last_event_seconds": silent, "silent_over_4x_median": over}
        if over:
            cessation["statement"] = ("No event in this series from %s to the declared window end %s (%s seconds, %.1f times the median interval), "
                                      "with the sensor confirmed recording over that window. This is a bounded negative about this series as it was "
                                      "defined, nothing more: it does not show that a channel ended, changed or moved, and says nothing about other "
                                      "series, destinations or protocols." % (iso(distinct[-1]), iso(window_end), silent, silent / median))
        else:
            cessation["statement"] = ("The series has events up to %s seconds before the declared window end; no silence longer than four median "
                                      "intervals is observed at its end." % silent)

    PROGRESS["stage"] = "writing the interval list"
    page = LosslessPage("beacon_intervals", limit)
    tsv = None
    tsv_path = None
    listed, list_cut = 0, False
    try:
        if out_dir:
            os.makedirs(out_dir, exist_ok=True)
            tsv_path = os.path.join(out_dir, "intervals.tsv")
            tsv = open(tsv_path, "w", encoding="utf-8", newline="\n")
            tsv.write("index\tfrom_utc\tto_utc\tseconds\tfrom_input_index\tto_input_index\n")
        for i in range(len(intervals)):
            if i & 4095 == 4095 and time.monotonic() > deadline + EXTRA_FOR_LIST:
                list_cut = True
                break
            a, b, gap = distinct[i], distinct[i + 1], intervals[i]
            row = {"index": i, "from": iso(a), "to": iso(b), "seconds": gap, "from_input_index": first_at[i], "to_input_index": first_at[i + 1]}
            page.add(row)
            if tsv is not None:
                tsv.write("%d\t%s\t%s\t%s\t%d\t%d\n" % (i, row["from"], row["to"], gap, row["from_input_index"], row["to_input_index"]))
            listed += 1
        pages = page.finish()
    except OSError as exc:
        fail("the interval list could not be written (%s)" % describe(exc), out_dir=out_dir)
    finally:
        if tsv is not None:
            tsv.close()

    rejected_total = sum(rejected.values())
    partial = timed_out_at is not None or list_cut or rejected_total > 0
    not_scored = ("%d of the %d values supplied %s not scored (%s) and %s not in the measurements, which cover the other %d; each is named by "
                  "position in first_rejected and all_rejected" % (rejected_total, supplied, "was" if rejected_total == 1 else "were", ", ".join("%d %s" % (n, r.replace("_", " ")) for r, n in rejected.items() if n), "is" if rejected_total == 1 else "are", count))
    if timed_out_at is not None:
        basis = ("the tool's own clock (max_seconds %s, of which reading takes the first two fifths: the measurement after it takes as long again or more) ran out "
                 "while the series was being read, at input position %d: the answer measures the %d values read before it, and nothing after them"
                 % (seconds_allowed, timed_out_at, supplied))
    elif list_cut:
        basis = ("the series was measured whole, but the interval list stopped at the tool's clock after %d of %d intervals: the list in the files is "
                 "incomplete, the measurements are not" % (listed, len(intervals)))
    elif rejected_total:
        basis = "the whole series was read and every interval of the scored values is in the list, but " + not_scored
    else:
        basis = "the whole series was read and measured; every interval is in the list"
    if rejected_total and (timed_out_at is not None or list_cut):
        basis += "; also " + not_scored
    if assumed and not rejected_total:
        basis += "; %d times carried no zone and were read as UTC because assume_utc was true" % assumed
    answer_out(json.dumps({
        "tool": TOOL,
        "status": "partial" if partial else "complete", "status_basis": basis,
        "series_complete": timed_out_at is None,
        "stopped_reading_at_input_index": timed_out_at,
        "interval_list_complete": not list_cut,
        "label": label,
        "events": count,
        "distinct_events": len(distinct),
        "duplicate_timestamps": count - len(distinct),
        "values_supplied": supplied,
        "all_values_scored": rejected_total == 0,
        "rejected": rejected,
        "first_rejected": first_rejected,
        "all_rejected": rejected_pages.get("all_results"),
        "first_rejected_note": "position, reason and length only: the text of a rejected value is not printed; the first five are inline and every one is in all_rejected (JSON Lines) when there are more",
        "naive_timestamps_assumed_utc": assumed,
        "first": iso(distinct[0]), "last": iso(distinct[-1]),
        "span_seconds": round(span, 3),
        "median_interval_seconds": round(median, 3),
        "median_absolute_deviation_seconds": round(mad, 3),
        "mad_over_median": round(relative, 4) if relative is not None else None,
        "shape": shape_of(relative),
        "shape_cutoffs": "mad_over_median <= 0.02 tight_cluster, <= 0.25 clustered, <= 0.6 loose_cluster, above dispersed: conventions of this tool",
        "event_density_ratio": round(density, 3) if density else None,
        "intervals": {"count": len(intervals), "min_seconds": min(intervals), "max_seconds": max(intervals)},
        "intervals_inline": [r["seconds"] for r in page.page],
        "intervals_page": pages,
        "intervals_tsv": sealed_path(tsv_path),
        "input_index_note": "from_input_index and to_input_index are positions in the series you supplied (0-based; in a timestamps_file, among its non-comment lines), the first occurrence when a time is repeated",
        "lines_over_limit": counters["long_lines"],
        "long_final_gap": final_gap,
        "observation_window": {"declared_end": iso(window_end) if window_end is not None else None},
        "cessation": cessation,
        "note": "A tight cluster is a measurement, not a verdict: update checks, telemetry, NTP, revocation checks and monitoring agents are all "
                "more regular than most malware, and a command channel can be irregular, or one long connection with no schedule at all. Set the "
                "median interval and the transfer sizes against comparable hosts and services, and corroborate with host or service evidence "
                "before calling a series anything. event_density_ratio compares the distinct events with the count a constant schedule at the "
                "median would give over the span; below 1 it does not say events are missing. A long final gap is an interval that ended in "
                "another event; cessation is assessed only with a declared window and a confirmed sensor.",
    }, indent=2))


ANSWERING = [False]             # the final answer is being written: a stop signal after that must not write a second document


def answer_out(text):
    """Write the final answer. `text` is already serialized (a stop signal while a large answer is still being serialized finds no document yet
    and writes its own), and the flag the handler reads is set only now: from here the handler lets the answer finish and the call ends with it."""
    hold_stop_signals()
    ANSWERING[0] = True
    print(text, flush=True)


if __name__ == "__main__":
    exit_code = 0
    try:
        main()
    except SystemExit as stop:
        exit_code = _code(stop)
    except Stopped as stop:
        drop_temps()
        print(json.dumps({"tool": TOOL, "status": "partial", "ok": False,
                          "status_basis": "the tool was stopped by signal %d while it was %s; no measurement had been answered yet" % (stop.signum, PROGRESS["stage"]),
                          "interrupted_by_signal": stop.signum, "values_read": PROGRESS["values_read"]}), flush=True)
        exit_code = 128 + stop.signum
    except Exception as exc:  # never an empty or clean answer for a failure
        hold_stop_signals(quietly=True)
        try:
            fail("unexpected failure: %s" % describe(exc))
        except SystemExit as stop:
            exit_code = _code(stop)
    _leave(exit_code)
