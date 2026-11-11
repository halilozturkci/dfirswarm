#!/usr/bin/env python3
"""Measure Shannon entropy across a file, window by window.

Shannon entropy over a window of bytes measures how evenly the byte values are spread: English text sits
around 4.5 bits per byte, ordinary machine code around 6, and compressed or encrypted data close to 8.
That is all it measures. A high value is consistent with compression, encryption, embedded media or
random-looking data; it says nothing about intent, and it does not identify packing by itself. What makes a
value worth examining is where it is: an executable section, a region inside an otherwise ordinary file, a
run that starts at a section boundary. Installers, signed binaries with compressed resources and archives
all read high.

The whole profile is written to a file, one row per window, and never to a file another call wrote: the name
is chosen from the source (or by the caller), and a name already taken gets a new one, with the earlier file
named in the answer. The profile file is created exclusively, mode 0600. A window that would give the file
more rows than MAX_PROFILE_ROWS is refused before anything is read, with the smallest window that fits named:
nothing is cut. The answer holds a preview of the profile (at most MAX_PREVIEW windows), the high-entropy runs
(the whole list in a file when there are more than the answer holds), the overall entropy, the bytes actually
processed and whether the pass finished. A window counts as high when its UNROUNDED entropy is >= the
threshold. The clock is looked at every MiB inside a window, so a 64 MiB window cannot run seconds past
max_seconds; a window the clock stopped is not written, and the answer names the last whole one.
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
            sys.stderr.flush()
            os.write(2, ("%s\n" % (code,)).encode("utf-8", "backslashreplace"))
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


import errno
import hashlib
import heapq
import json
import math
import os
import re
import stat
import sys
import time
from collections import Counter
from pathlib import Path

PAGES = []                          # the pagers of this call: the stop block removes a temporary file of each (these write none)

# BEGIN SHARED STOP
# The same text is in every tool that carries this block (tests/pack-shared-stop.test.ts holds the copies equal). SIGTERM, SIGINT and SIGHUP end the tool with JSON
# (status failed with interrupted true: a stop is not a status, the statuses are complete, partial and failed; exit 128 + the signal) and remove the temporary file a page was writing; the tool's own clock (set_deadline) is below the manifest's.
# The handlers are in as soon as the module has run as far as this block, with a minimal last word until main() installs the tool's own (only
# the start of the interpreter and the compiling of the file come before it). The first signal counts: a second one does nothing while the
# first is answered. print_answer holds the stop signals back while the answer is printed, so exactly one complete document is written
# (the ransomware tools print through it; the windows tools hold the signals in the emit of their boundary block, and carry this text unused).
import signal
import time

STOP = {"last_word": None, "deadline": None}


def set_deadline(seconds):
    STOP["deadline"] = time.monotonic() + seconds


def out_of_time():
    return STOP["deadline"] is not None and time.monotonic() > STOP["deadline"]


def _on_signal(signum, _frame):
    for other in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(other, signal.SIG_IGN)
    for page in list(globals().get("PAGES", ())):
        tmp = getattr(page, "_tmp", None)
        if tmp is not None:
            try:
                os.unlink(tmp)
            except OSError:
                pass
    last_word = STOP["last_word"]
    if last_word:
        try:
            last_word(signum)
        except Exception:  # noqa: BLE001 - a last word is best effort
            pass
    if "answer_a_stop" in globals():     # (a block run on its own, by a test, has no ENDS block)
        answer_a_stop(signum)
    os._exit(128 + signum)


def install_signal_handlers(last_word=None):
    STOP["last_word"] = last_word
    for signum in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(signum, _on_signal)


def interrupted_answer(signum, **extra):
    print(json.dumps({"error": "stopped by signal %d before the answer was complete" % signum, "status": "failed", "interrupted": True,
                      "status_basis": "the tool was stopped by signal %d; nothing it had read is an answer" % signum,
                      "signal": signum, **extra}), flush=True)


def print_answer(answer, **dumps_kwargs):
    """Print the answer with the stop signals held back: a signal that came in the middle of the write would end the process there, with the
    answer cut. A signal that is held is not answered once the answer is out (the shared ENDS block): the answer stands, and the call ends
    with its own exit code."""
    try:
        signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGTERM, signal.SIGINT, signal.SIGHUP})
    except (AttributeError, ValueError, OSError):
        pass
    hold_stop_signals()
    STOP["last_word"] = None
    print(json.dumps(answer, **dumps_kwargs))


install_signal_handlers(lambda signum: interrupted_answer(signum))
# END SHARED STOP

TOOL = {"name": "entropy_map", "version": 8}
PARSER = "entropy_map/3"
SCHEMA_VERSION = 2
MAX_WINDOW = 1 << 26                    # 64 MiB: one window is held in memory at a time
MIN_WINDOW = 64
MAX_INLINE_RUNS = 1000                  # runs held in memory and in the answer; the whole list is a file past this
MAX_PREVIEW = 10_000                    # windows of the profile in the answer; the whole profile is in the file
MAX_PROFILE_ROWS = 4_000_000            # rows the profile file may hold (about 120 MB): a window that would give more is refused, not cut
READ_PIECE = 1 << 20                    # bytes read between two looks at the clock
DEFAULT_SECONDS = 270                   # the tool's own clock, below the manifest's 300 s: a file too big for it is a partial answer, not a kill
MAX_SECONDS = 280
NAME_RX = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$")


def describe(exc):
    code = errno.errorcode.get(exc.errno, "") if getattr(exc, "errno", None) else ""
    return "%s%s: %s" % (type(exc).__name__, " " + code if code else "", getattr(exc, "strerror", None) or str(exc))


def fail(message, **extra):
    print_answer({"error": message, "status": extra.pop("status", "failed"), "status_basis": extra.pop("status_basis", message), "tool": TOOL,
                  "problems": [], "limits_hit": [], **extra})
    raise SystemExit(1)


def file_problem(path):
    """Why `path` is not a file this tool can read, in words that fit: a missing file, a directory, a pipe, a loop."""
    try:
        mode = os.stat(path).st_mode
    except FileNotFoundError:
        return "no such file"
    except OSError as exc:
        return "the file could not be examined: %s" % describe(exc)
    if stat.S_ISREG(mode):
        return None
    kinds = ((stat.S_ISDIR, "a directory"), (stat.S_ISFIFO, "a named pipe"), (stat.S_ISSOCK, "a socket"), (stat.S_ISBLK, "a block device"),
             (stat.S_ISCHR, "a character device"))
    return "not a regular file (%s)" % next((n for t, n in kinds if t(mode)), "a special file")


def entropy_of(counts, total):
    out = 0.0
    for c in counts.values():
        p = c / total
        out -= p * math.log2(p)
    return out


def output_dir():
    """Where a file this tool writes goes: under $OUT when there is one (a job's output, or a recipe's), otherwise under
    work/<agent>/tool-output, the agent's own place."""
    out = os.environ.get("OUT")
    if out:
        return Path(out)
    agent = re.sub(r"[^A-Za-z0-9_.-]", "_", os.environ.get("AGENT_ID") or "tool")
    return Path("work") / agent / "tool-output"


def own_dir(path):
    """Create the tool-output directory and return None, or say why it is not used: a symbolic link anywhere on the way (the directory itself,
    or work/ or the agent's directory under it) would send the tables and the private names file somewhere else, and O_NOFOLLOW guards only
    the last name of a file. In a job only the part under $OUT is checked ($OUT is the job service's)."""
    path = Path(path)
    out = os.environ.get("OUT")
    start = len(Path(out).parts) if out and path.parts[:len(Path(out).parts)] == Path(out).parts else 0
    for i in range(max(start, 1), len(path.parts) + 1):
        step = Path(*path.parts[:i])
        if os.path.islink(step):
            return "%s is a symbolic link: refused, nothing written through it" % step
    path.mkdir(parents=True, exist_ok=True)
    return None


def create_unique(directory, name):
    """Create a new file `name` in `directory`, exclusively, mode 0600; a name that is taken gets -2, -3, ... before its extension.
    Returns (path, file object, name used). Nothing that exists is replaced or followed."""
    refused = own_dir(directory)
    if refused:
        raise OSError(errno.EPERM, refused)
    stem, dot, ext = name.rpartition(".")
    if not dot:
        stem, ext = name, ""
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    for n in range(1, 1000):
        candidate = name if n == 1 else "%s-%d%s" % (stem, n, "." + ext if ext else "")
        try:
            fd = os.open(str(directory / candidate), flags, 0o600)
        except FileExistsError:
            continue
        return directory / candidate, os.fdopen(fd, "w", encoding="utf-8"), candidate
    raise OSError(errno.EEXIST, "a thousand files of this name already exist in %s" % directory)


def main():
    install_signal_handlers(lambda signum: interrupted_answer(signum, tool=TOOL))
    try:
        args = json.load(sys.stdin)
    except (ValueError, RecursionError) as exc:
        fail("arguments are not valid JSON", reason=str(exc))
    if not isinstance(args, dict):
        fail("arguments must be a JSON object")
    path = args.get("path")
    if not isinstance(path, str) or not path:
        fail("path is required: the file to measure")
    why_not = file_problem(path)
    if why_not:
        fail(why_not, path=path)
    window = args.get("window", 4096)
    if not isinstance(window, int) or isinstance(window, bool) or not MIN_WINDOW <= window <= MAX_WINDOW:
        fail("window must be an integer from %d to %d" % (MIN_WINDOW, MAX_WINDOW))
    threshold = args.get("threshold", 7.2)
    if not isinstance(threshold, (int, float)) or isinstance(threshold, bool) or not 0 < threshold <= 8:
        fail("threshold must be a number above 0 and at most 8")
    max_windows = args.get("max_windows", 256)
    if not isinstance(max_windows, int) or isinstance(max_windows, bool) or not 1 <= max_windows <= MAX_PREVIEW:
        fail("max_windows must be an integer from 1 to %d (the windows shown in the answer; the whole profile is in the file)" % MAX_PREVIEW)
    seconds = args.get("max_seconds", DEFAULT_SECONDS)
    if isinstance(seconds, bool) or not isinstance(seconds, int) or not 1 <= seconds <= MAX_SECONDS:
        fail("max_seconds must be an integer from 1 to %d" % MAX_SECONDS)
    requested = args.get("output_name")
    if requested is not None and (not isinstance(requested, str) or not NAME_RX.match(requested)):
        fail("output_name must be a plain file name: letters, digits, '.', '_' and '-', not starting with a dot, no path")

    try:
        size = os.path.getsize(path)
    except OSError as exc:
        fail("the file could not be examined: %s" % describe(exc), path=path)
    if not size:
        fail("the file is empty", path=path)
    rows = -(-size // window)
    if rows > MAX_PROFILE_ROWS:
        smallest = max(MIN_WINDOW, -(-size // MAX_PROFILE_ROWS))
        fail("a window of %d bytes over this file of %d bytes would give %d rows, more than the %d the profile file may hold: nothing was read; the smallest window that fits is %d bytes"
             % (window, size, rows, MAX_PROFILE_ROWS, smallest), path=path, bytes=size, window=window, rows_needed=rows, max_profile_rows=MAX_PROFILE_ROWS,
             smallest_window_that_fits=smallest)

    try:
        source = open(path, "rb")
    except OSError as exc:
        fail("the file could not be opened: %s" % describe(exc), path=path)
    directory = output_dir()
    digest = hashlib.sha256(json.dumps([os.path.realpath(path), window]).encode("utf-8", "surrogatepass")).hexdigest()[:12]
    wanted = requested or "entropy-windows-%s-w%d.tsv" % (digest, window)
    try:
        profile_path, profile, profile_name = create_unique(directory, wanted)
    except OSError as exc:
        source.close()
        fail("the complete profile could not be created in %s: %s" % (directory, describe(exc)), path=path)
    preview = []
    totals = Counter()
    windows = high_windows = processed = 0
    profile.write("offset\tbytes\tentropy\n")
    # from here a stop signal names the profile it leaves and how far the pass got (the variables are read when the signal arrives)
    install_signal_handlers(lambda signum: interrupted_answer(signum, tool=TOOL, path=path, profile_file=profile_name, bytes_processed=processed, windows_measured=windows, profile_complete=False))

    last_bytes = 0
    problems = []
    run_count = 0
    current = None
    first_runs = []                      # runs in the order found, held only until there are more than the answer holds
    biggest = []                         # a heap of the largest runs: (bytes, -start, run)
    runs_file = runs_name = None
    runs_name_wanted = re.sub(r"\.tsv$", "", profile_name) + "-runs.tsv"

    def finish_run(run):
        nonlocal run_count, runs_file, runs_name
        run["bytes"] = run["end"] - run["start"]
        run_count += 1
        item = (run["bytes"], -run["start"], run_count, run)
        if len(biggest) < MAX_INLINE_RUNS:
            heapq.heappush(biggest, item)
        else:
            heapq.heappushpop(biggest, item)
        if runs_file is None and run_count <= MAX_INLINE_RUNS:
            first_runs.append(run)
            return
        if runs_file is None:
            _p, runs_file, runs_name = create_unique(directory, runs_name_wanted)
            runs_file.write("start\tend\tbytes\tpeak\n")
            for kept in first_runs:
                runs_file.write("%d\t%d\t%d\t%.6f\n" % (kept["start"], kept["end"], kept["bytes"], kept["peak"]))
            first_runs.clear()
        runs_file.write("%d\t%d\t%d\t%.6f\n" % (run["start"], run["end"], run["bytes"], run["peak"]))

    def read_window(fh):
        """(counts, bytes) of the next window, read a MiB at a time with a look at the clock between the pieces. A window the clock stopped is
        (None, bytes read of it): it is not measured, and the profile ends at the last whole window."""
        counts, got = Counter(), 0
        while got < window:
            if got and time.monotonic() > deadline:
                return None, got
            piece = fh.read(min(READ_PIECE, window - got))
            if not piece:
                break
            counts.update(piece)
            got += len(piece)
        return counts, got

    complete = True
    deadline = time.monotonic() + seconds
    try:
        with source as fh:
            offset = 0
            while True:
                if time.monotonic() > deadline:
                    problems.append("the pass stopped at max_seconds (%d) after %d of %d bytes (%d whole windows): the profile holds the windows measured so far" % (seconds, processed, size, windows))
                    complete = False
                    break
                try:
                    counts, got = read_window(fh)
                except OSError as exc:
                    problems.append("a read failed after %d bytes: %s" % (processed, describe(exc)))
                    complete = False
                    break
                if counts is None:
                    problems.append("the pass stopped at max_seconds (%d) inside the window at offset %d, after %d of its %d bytes: that window is not measured, "
                                    "and the profile ends at the last whole window (%d windows, %d bytes)" % (seconds, offset, got, window, windows, processed))
                    complete = False
                    break
                if not got:
                    break
                totals.update(counts)
                raw = entropy_of(counts, got)
                value = round(raw, 6)
                windows += 1
                processed += got
                last_bytes = got
                if len(preview) < max_windows:
                    preview.append({"offset": offset, "bytes": got, "entropy": value})
                profile.write("%d\t%d\t%.6f\n" % (offset, got, raw))
                if raw >= threshold:
                    high_windows += 1
                    if current is None:
                        current = {"start": offset, "end": offset + got, "peak": value}
                    else:
                        current["end"] = offset + got
                        current["peak"] = max(current["peak"], value)
                elif current is not None:
                    finish_run(current)
                    current = None
                offset += got
            if current is not None:
                finish_run(current)
    except OSError as exc:
        problems.append("the pass stopped after %d bytes: %s" % (processed, describe(exc)))
        complete = False
    finally:
        try:
            profile.flush()
            os.fsync(profile.fileno())
            profile.close()
            if runs_file is not None:
                runs_file.flush()
                os.fsync(runs_file.fileno())
                runs_file.close()
        except OSError as exc:
            problems.append("writing the profile failed: %s" % describe(exc))
            complete = False
    if processed != size and complete:
        problems.append("the file is %d bytes and %d were processed (it changed while it was read, or it is not a regular file)" % (size, processed))
        complete = False

    runs = [item[3] for item in sorted(biggest, key=lambda i: (-i[0], -i[1]))] if runs_name else sorted(first_runs, key=lambda r: (-r["bytes"], r["start"]))
    overall = entropy_of(totals, processed) if processed else 0.0
    status = "complete" if complete else ("partial" if processed else "failed")
    result = {
        "tool": TOOL,
        "parser": PARSER,
        "schema_version": SCHEMA_VERSION,
        "path": path,
        "bytes": size,
        "bytes_processed": processed,
        "status": status,
        "status_basis": ("every window of the file was measured and written to the profile" if complete else
                         problems[0] if problems else "the pass did not finish"),
        "problems": problems,
        "window": window,
        "threshold": threshold,
        "threshold_basis": "a window is high when its unrounded entropy is >= the threshold; values are written to 6 decimals",
        "overall_entropy": round(overall, 6),
        "windows_measured": windows,
        "final_window_bytes": last_bytes,
        "high_entropy_windows": high_windows,
        "high_entropy_run_count": run_count,
        "high_entropy_runs": runs,
        "profile": preview,
        "profile_complete": complete,
        "max_seconds": seconds,
        "inline_profile_complete": len(preview) == windows,
        "profile_file": profile_name,
        "profile_written_to": str(profile_path),
        "note": "Entropy is a measurement of how evenly byte values are spread: around 4.5 bits per byte is text, around 6 machine code, "
                "close to 8 compressed or encrypted data, and a high value is a feature of the bytes, not a finding. Installers, signed "
                "binaries with compressed resources, archives and media all read high. What makes a run worth examining is where it "
                "starts: an executable section, or a region inside an otherwise ordinary file. It does not identify packing by itself.",
    }
    if profile_name != wanted:
        result["earlier_file_kept"] = wanted
        result["name_note"] = "a file named %s already existed and was left as it was; this profile is %s" % (wanted, profile_name)
    if runs_name:
        result["runs_file"] = runs_name
        result["runs_file_format"] = "tab-separated: start, end, bytes, peak entropy; every run, in the order found"
    if not complete:
        result["error"] = problems[0] if problems else "the pass did not finish"
    print_answer(result, indent=2)
    if not processed:
        raise SystemExit(1)


if __name__ == "__main__":
    exit_code = 0
    try:
        try:
            main()
        except SystemExit:
            raise
        except Exception as exc:  # never a traceback and never a clean answer for a failure
            hold_stop_signals(quietly=True)
            fail("unexpected failure: %s" % (describe(exc) if isinstance(exc, OSError) else "%s: %s" % (type(exc).__name__, exc)))
    except SystemExit as stop:
        exit_code = _code(stop)
    _leave(exit_code)
