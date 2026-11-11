#!/usr/bin/env python3
"""Read auth.log and secure as records rather than as text.

What this exists to get right, because doing it by hand with grep is where the mistakes are.

Rotation. The current file usually covers days, and an intrusion usually is not in it. auth.log.1,
auth.log.2.gz and the rest hold the rest. They are read oldest first by the suffix the rotation scheme
wrote (a number, a date, or none for the live file); the answer says which basis ordered each file and
whether the files' own time ranges agree with that order.

The missing year and the missing zone. A traditional syslog line carries a month, a day and a time and
no year and no zone, so every date is an inference until something supplies one. The year applied comes
from the file's modification time (which is the time of extraction on a copied tree) or from the
caller's `year`; the answer says which, per file, and each record carries its stamp as written
(`time_raw`), the year applied and `time_zone: "unknown"`. A year is counted only where the months wrap
forward through the year end; a line out of order by months is flagged `reordered` and placed by its
nearness to the lines around it, never counted as a second year end. An RFC 3339 stamp keeps its own
offset and its fraction of a second.

The shape of each line. "Accepted publickey for deploy from 10.0.0.5 ... ssh2: ED25519 SHA256:..."
names a key, not a person: the fingerprint maps to an entry in some authorized_keys file and says
nothing about when that entry was made. A PAM session is the named service's session (sshd, sudo, cron
and others), not necessarily a login. A line that matches no rule stays `other`, with its text.

THE SECRET-SAFE OUTPUT PATTERN (docs/packs.md, "Secrets and sensitive output"). A sudo line carries a
whole command line, and a name typed at a prompt can be a password typed into the wrong field. The answer
therefore carries fields and locators (file, physical line, byte offset), the length of the text and never
the text: `raw` and `command` are in a file under $OUT only when `write_text: true` is asked, in a job, and
in the answer only with `preview_text: true`, in a job. The skill says the job runs with secret_output:
true. Nothing is hashed, and a secret never goes on a command line: this tool takes a path and flags.

A tool that fails loudly: a file it cannot open or read to its end is a named, partial file and not an
empty one; a line no rule places is counted, located and kept; `all_lines_parsed` is true only when every
line matched a syslog shape and every file was read through.
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


import datetime
import gzip
import ipaddress
import itertools
import json
import math
import os
import re
import secrets
import signal
import stat
import sys
import tempfile
import time
import zlib
from pathlib import Path

TOOL = "auth_log"
PARSER = "auth_log/16"


# BEGIN LINUX STOP
# The same text is in auth_log, cron_dump, shell_history and utmp_parse (tests/pack-linux-parts.test.ts holds the copies equal); journal_export's
# stop is its SHARED PROCESS block. A signal ends the tool with a last word. The harness ends a tool that runs too long with SIGTERM before it
# kills the group, and a tool that ignored it left its paging files as unfinished temporary files nobody could name. The rows written so far are
# kept under their final names and the text file is closed, so the last word can say where they are; the answer itself was never built.
#
# This block comes right after TOOL and PARSER and installs the handlers as its last line, before any parts, constants or arguments exist: a
# signal from then on gets one document (until the parts below are defined there is no page or text file to name, and the document says
# none was kept). What is before it is the interpreter's own start-up and the imports, which no code of this file can cover.
#
# Two moments are not the handler's. Python can run a handler inside a buffered file's own write (its flush looks for signals between
# writes), and there the file refuses the last word's flush: a signal that came while a row was being written left that paging file
# unfinished and unnamed. So while a file the last word closes is being written, the handler only notes the signal, and the write
# gives the last word once it is done. And while the answer, or an error answer, is being written, a signal is not answered: the
# answer stands, and no second document follows it. The last word disarms the regex clock (SIGALRM) before anything else, and a file
# that cannot be flushed inside it is named with its error and does not start an error document of its own (STATE["stopping"]). One
# window cannot be closed from inside Python: an alarm that is already pending when a stop signal arrives runs its handler at the
# first instruction of the last word, in the last word's frame, and the exception it raises there is taken by the tool's own
# expression-timeout handling; the tool then ends partial within max_seconds and not at the signal.
STATE = {"pages": [], "text": None, "writing": 0, "pending": None, "answering": False, "stopping": False}


def _writing():
    STATE["writing"] += 1


def _written():
    STATE["writing"] -= 1
    if not STATE["writing"] and STATE["pending"] is not None:
        signum, STATE["pending"] = STATE["pending"], None
        _on_signal(signum, None)


def _on_signal(signum, _frame):
    if hasattr(signal, "setitimer"):
        try:
            signal.setitimer(signal.ITIMER_REAL, 0)     # the regex clock stops first: its alarm inside the last word left a paging file unnamed
            signal.signal(signal.SIGALRM, signal.SIG_IGN)
        except BaseException:  # noqa: BLE001
            pass
    if STATE["answering"]:
        return
    if STATE["writing"]:
        STATE["pending"] = signum
        return
    STATE["answering"] = STATE["stopping"] = True       # the last word is the answer now: a second signal does not start another
    kept, unflushed = {}, []
    for page in STATE["pages"]:
        try:
            shown = page.stop_here()
        except BaseException:  # noqa: BLE001 - a last word is best effort
            shown = None
        if shown:
            kept[page.key] = shown
        if getattr(page, "stop_error", None):
            unflushed.append(page.key)
    text = STATE["text"]
    text_file = getattr(text, "shown", None) if text is not None and getattr(text, "written", 0) else None
    if text is not None:
        try:
            text.close()
        except BaseException:  # noqa: BLE001
            pass
    try:
        sys.stdout.write(json.dumps({
            "parser": PARSER, "status": "failed", "stopped_by_signal": signum,
            "status_basis": "this tool was stopped by signal %d before it finished: no answer was built, and what it had read is not a complete result" % signum,
            "paging_files_kept": kept, "paging_files_not_flushed": unflushed, "text_file_kept": text_file,
            "text_file_close_error": getattr(text, "close_error", None),
            "kept_note": "the rows each file holds were written in the order read, up to where the tool was stopped; the files are named here and nowhere else",
        }) + "\n")
        sys.stdout.flush()
    except Exception:  # noqa: BLE001
        pass
    if "answer_a_stop" in globals():     # (a block run on its own, by a test, has no ENDS block)
        answer_a_stop(signum)
    os._exit(128 + signum)


def install_signal_handlers():
    for signum in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(signum, _on_signal)


install_signal_handlers()
# END LINUX STOP
DEFAULT_LIMIT = 200
FIRST_FAILURES = 20
# The year of a traditional line is inferred (see the manifest). A forward step between two consecutive in-order lines of more
# than STEP_DAYS days is reported, because the year is assumed to advance by the least the months allow across it; and the
# modification time that anchors the year is flagged as possibly the time of a copy when it is more than COPY_DAYS after the last
# dated line, when every file of the call shares one time to within SAME_MTIME_SECONDS, or when a gzip header time differs from it
# by more than GZ_AGREE_SECONDS (FAT keeps two-second times).
STEP_DAYS = 62
STEP_INLINE = 20            # forward steps shown inline per file; the whole list is in pages.forward_steps
COPY_DAYS = 7
SAME_MTIME_SECONDS = 10
GZ_AGREE_SECONDS = 2
MAX_YEARS = 1000            # entries of the `years` argument
YEAR_MIN, YEAR_MAX = 1970, 2200
MAX_LINE = 64 << 10         # a physical line longer than this is located, not parsed
DEFAULT_EXPANDED = 1 << 30  # a gzip stream is read to at most this many decompressed bytes
DEFAULT_SECONDS = 100.0     # the manifest allows 120
MAX_SECONDS = 105.0           # the most a caller may ask for (the manifest allows 120)
ZONE_SLACK = datetime.timedelta(hours=26)   # the log's zone is unknown: UTC-12 to UTC+14 is 26 hours
TEXT_NAME = "auth-text.jsonl"

MONTHS = {m: i + 1 for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"])}


# BEGIN LINUX PARTS
# ---- The parts every tool of this pack that pages or keeps text copies (a tool is standalone; none imports another) ----
# The same text is in auth_log, cron_dump, journal_export, shell_history and utmp_parse (tests/pack-linux-parts.test.ts holds the copies
# equal). It uses STATE, _writing and _written, which are LINUX STOP's in four tools and, in journal_export, whose stop is its SHARED PROCESS
# block, two stand-ins below the SHARED PROCESS block's STATE.


def fail(message, **extra):
    """An error answer: JSON, exit 1, and the same `status` every answer of this pack carries."""
    if hasattr(signal, "pthread_sigmask"):
        signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGTERM, signal.SIGINT, signal.SIGHUP})     # one document: the stop handlers may not be in yet (a refusal can come before main() installs them), and one that is in would write a second, false, document after this one; a stop that arrives while this is written waits, and the tool leaves with it
    hold_stop_signals()
    STATE["answering"] = True       # a signal from here on is not answered: this answer stands alone
    print(json.dumps({"error": message, "status": "failed", "status_basis": "the tool stopped with an error (see error)", **extra}))
    raise SystemExit(1)


def describe(exc):
    return "%s: %s" % (type(exc).__name__, exc)


def in_job():
    return bool(os.environ.get("JOB_ID") and os.environ.get("OUT"))


def read_args():
    try:
        args = json.load(sys.stdin)
    except ValueError as exc:
        fail("arguments are not valid JSON", reason=str(exc))
    if not isinstance(args, dict):
        fail("arguments must be a JSON object")
    return args


def want_str(args, key, required=None):
    value = args.get(key)
    if value is None:
        if required:
            fail(required)
        return None
    if not isinstance(value, str):
        fail("%s must be a string" % key)
    if required and not value:
        fail(required)
    return value


def want_str_list(args, key):
    value = args.get(key)
    if value is None:
        return []
    if not isinstance(value, list) or not all(isinstance(x, str) for x in value):
        fail("%s must be a list of strings" % key)
    return value


def want_seconds(args, key, default, maximum=3600):
    """A time budget: a finite number above zero and no more than `maximum` (NaN and Infinity are not budgets)."""
    value = args.get(key, default)
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value <= 0 or value > maximum:
        fail("%s must be a number of seconds above 0 and at most %d" % (key, maximum))
    return float(value)


def decode(data):
    """Bytes as text with no byte lost: an undecodable byte is a lone surrogate, which the text file writes as an escape
    and which encodes back to the byte (`blen` counts the bytes the original had)."""
    return data.decode("utf-8", "surrogateescape")


def blen(text):
    return len(text.encode("utf-8", "surrogateescape"))


def bound(value, limit=1024):
    """(shown, bytes or None): a string longer than `limit` characters is shown cut, with its whole length. The
    whole is kept where the record's text is kept (the text file, the evidence at the record's locator)."""
    if isinstance(value, str) and len(value) > limit:
        return value[:limit], blen(value)
    return value, None


def want_flag(args, key):
    value = args.get(key, False)
    if not isinstance(value, bool):
        fail("%s must be true or false" % key)
    return value


def want_limit(args):
    limit = args.get("limit", DEFAULT_LIMIT)
    if isinstance(limit, bool) or not isinstance(limit, int) or limit < 1:
        fail("limit must be a positive integer")
    return limit


def status_of(complete, failed, basis_complete, basis_partial, basis_failed):
    """The `status` every answer of this pack carries, with the reason for it: complete (everything the request asked
    for was read and nothing was left out), partial (some of it was, and the answer names what was not) or failed."""
    if failed:
        return {"status": "failed", "status_basis": basis_failed}
    if complete:
        return {"status": "complete", "status_basis": basis_complete}
    return {"status": "partial", "status_basis": basis_partial}


def touches_withheld_text(has_filter):
    """A filter that matches the text of a record is a search over text the answer withholds: it is honoured only in a job
    (whose output is sealed), and the answer says it was used."""
    return bool(has_filter) and in_job()


MAX_PAGING_BYTES = 128 << 20  # all the paging files of one call hold this much together; a row past it is counted and located, not written
MAX_TEXT_BYTES = 256 << 20    # the text file of one call holds this much; a record past it is counted and located, not written
PAGING = {"left": MAX_PAGING_BYTES}      # what the paging files of this call may still hold, in bytes, all of them together
TEXTING = {"left": MAX_TEXT_BYTES}       # what the text file may still hold, in bytes


# Lossless paging (the same in every library tool that pages): the page an agent reads stays small, and when
# there are more rows the whole result is written as JSON Lines under work/<agent>/tool-output (in a job,
# $OUT/tool-output) and named. The file name is random: it is never a digest of anything asked for. A write
# that fails is an error answer naming the file, never a traceback and never a silent loss: the rows written
# before the error are kept under the file's name and the answer says so, or says the temporary was removed.
class LosslessPage:
    def __init__(self, tool, key, limit):
        if isinstance(limit, bool) or not isinstance(limit, int) or limit < 1:
            raise ValueError("limit must be a positive integer")
        self.tool = re.sub(r"[^A-Za-z0-9_.-]", "_", tool)
        self.limit = limit
        self.key = key
        self.page = []
        self.total = 0
        self.not_written = 0        # rows after the paging cap: counted in `total`, not in the file
        self.stop_error = None
        self._out = None
        self._tmp = None
        name = "%s-%s.jsonl" % (self.tool, secrets.token_hex(8))
        job, out = os.environ.get("JOB_ID"), os.environ.get("OUT")
        if job and out:
            # In a job only $OUT is written, and it is sealed as the job's output: the whole result is cited from there.
            self.path = Path(out) / "tool-output" / name
            self.shown = "store/jobs/%s/out/tool-output/%s" % (re.sub(r"[^A-Za-z0-9_.-]", "_", job), name)
        else:
            agent = re.sub(r"[^A-Za-z0-9_.-]", "_", os.environ.get("AGENT_ID") or "tool")
            self.path = Path("work") / agent / "tool-output" / name
            self.shown = str(self.path)
        self._done = False
        STATE.setdefault("pages", []).append(self)     # every page is the last word's to name, from the moment it exists

    def _abandon(self):
        """A write failed (ENOSPC, EIO): what is already in the temporary is kept under the file's own name, or the temporary is removed.
        Returns what the answer says about it."""
        out, self._out = self._out, None
        if out is not None:
            try:
                out.close()
            except OSError:
                pass
        if self._tmp is None:
            return "no paging file was left"
        try:
            os.replace(self._tmp, self.path)
            self._done = True
            return "the rows written before the error are in %s (the last row may be cut)" % self.path
        except OSError:
            pass
        try:
            os.unlink(self._tmp)
            return "the temporary paging file was removed"
        except OSError as exc:
            return "the temporary paging file %s could not be renamed or removed (%s)" % (self._tmp, describe(exc))

    def _write(self, row, kept=False):
        data = json.dumps(row, ensure_ascii=False, default=str) + "\n"
        size = len(data.encode("utf-8", "backslashreplace"))
        if not kept and (self.not_written or size > PAGING["left"]):
            self.not_written += 1       # once a row is refused no later one is written: the file stays the first rows in order
            return
        PAGING["left"] = max(0, PAGING["left"] - size)
        _writing()
        try:
            self._out.write(data)     # one write: a stop never leaves half a row
        except OSError as exc:
            fail("the whole result could not be written to %s: %s" % (self.path, describe(exc)), paging_file=str(self.path), paging_file_state=self._abandon())
        finally:
            _written()

    def add(self, row):
        self.total += 1
        if len(self.page) < self.limit:
            self.page.append(row)
            return
        if self._out is None:
            try:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                # The name is known before the file exists, so a signal at any point after this line finds the file by it.
                self._tmp = self.path.parent / (".%s-%s" % (self.path.name, secrets.token_hex(8)))
                fd = os.open(str(self._tmp), os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
                self._out = os.fdopen(fd, "w", encoding="utf-8", errors="backslashreplace")
            except OSError as exc:
                state = "no paging file was left" if self._tmp is None or not os.path.lexists(self._tmp) else self._abandon()
                fail("the whole result could not be written: %s cannot be created (%s)" % (self.path, describe(exc)), paging_file=str(self.path), paging_file_state=state)
            for kept in self.page:
                self._write(kept, kept=True)
        self._write(row)

    def stop_here(self):
        """The rows written so far, kept under the final name (a signal ended the tool): the path as shown, or None where nothing was written.
        A file that cannot be flushed is still renamed (what reached the disk is kept) and `stop_error` says it."""
        if self._tmp is None:
            return None
        if self._done:
            return self.shown           # finish() had put it under its name: it holds every row
        out, self._out = self._out, None
        if out is not None:
            try:
                out.flush()
                os.fsync(out.fileno())
            except OSError as exc:
                self.stop_error = describe(exc)
            try:
                out.close()
            except OSError as exc:
                self.stop_error = self.stop_error or describe(exc)
        if not os.path.exists(self._tmp):
            return None
        os.replace(self._tmp, self.path)
        return self.shown

    def finish(self):
        result = {"matched": self.total, "returned": len(self.page), "truncated": self.total > len(self.page)}
        if self._out is not None:
            _writing()
            try:
                self._out.flush()
                os.fsync(self._out.fileno())
                self._out.close()
                os.replace(self._tmp, self.path)
                self._done = True
            except OSError as exc:
                fail("the whole result could not be written to %s: %s" % (self.path, describe(exc)), paging_file=str(self.path), paging_file_state=self._abandon())
            finally:
                _written()
            result["all_results"] = self.shown
            result["all_results_format"] = "JSON Lines, one complete result per line"
        if self.not_written:
            result["not_written"] = self.not_written
            result["not_written_why"] = ("the paging files of one call hold at most %d bytes together: the first %d rows are in the file, in order; "
                                         "the %d after them are counted in `matched` and are in the evidence at the file and line each entry names"
                                         % (MAX_PAGING_BYTES, self.total - self.not_written, self.not_written))
        return result


def require_job(flag):
    """What leaves a record's text is held to the secret-safe output pattern (docs/packs.md, "Secrets and
    sensitive output"): the text goes into the answer or into a file only in a job, whose output the skill
    says to seal with secret_output: true. Outside a job, and in a job the harness did not run as secret output (it sets
    SECRET_OUTPUT=1 in the environment of such a job's process, from the manifest's declaration or the agent's flag), the
    request is refused and nothing is written."""
    if not in_job():
        fail("%s is refused outside a job: a command line, a message or an environment value written or "
             "printed here would be an ordinary file or an ordinary answer, not a sealed output. Run this as "
             "job_run tool=%s with secret_output: true, and ask again there. Nothing was written." % (flag, TOOL))
    if os.environ.get("SECRET_OUTPUT") != "1":
        fail("%s is refused: this job was not run as secret output, so what it wrote or printed would be sealed as an ordinary "
             "output. The harness sets SECRET_OUTPUT=1 for a secret job's process and it is not set here. Run this as "
             "job_run tool=%s with secret_output: true, and ask again there. Nothing was written." % (flag, TOOL))


class TextRefused(Exception):
    pass


class TextFile:
    """Where the text of a tool's records goes when, and only when, the caller asked for it.

    The secret-safe output pattern of recovery_key_scan's SecretValues, for rows. With `enabled` false it
    writes nothing and `summary()` says so. Enabled, it is refused outside a job; inside one the file is
    created before anything is read (mode 0600, exclusively: a file or a link already at that name is
    refused by name) under $OUT, and the answer names it and says it may hold secrets. A byte that is not
    UTF-8 is written as a JSON escape of its lone surrogate and reads back as the byte: the file keeps the whole.
    The file holds at most MAX_TEXT_BYTES: once a record would pass it, that record and every one after it are
    counted in `not_written` and not written (the file stays the first records, in order), and `summary()` says so.
    """

    def __init__(self, name, enabled, what, flag="write_text"):
        self.enabled = enabled
        self.written = 0
        self.not_written = 0        # records after the cap: counted, not in the file
        self.capped = False
        self.cut_record = False     # a record's first pieces (add_bytes_raw) were written and the cap came before its last
        self._open_piece = False
        self.close_error = None
        self.what = what
        self.flag = flag
        self._fh = None
        self.path = None
        self.shown = None
        if not enabled:
            return
        job, out = os.environ.get("JOB_ID") or "", os.environ.get("OUT") or ""
        if not (job and out):
            raise TextRefused("%s is refused outside a job: the text of the records written here would be an "
                              "ordinary file, not a sealed output. Run this as job_run tool=%s with secret_output: "
                              "true, and ask again there. Nothing was written." % (flag, TOOL))
        if os.environ.get("SECRET_OUTPUT") != "1":
            raise TextRefused("%s is refused: this job was not run as secret output, so the text of the records written here would be sealed "
                              "as an ordinary output. The harness sets SECRET_OUTPUT=1 for a secret job's process and it is not set here. "
                              "Run this as job_run tool=%s with secret_output: true, and ask again there. Nothing was written." % (flag, TOOL))
        self.path = Path(out) / name
        self.shown = "store/jobs/%s/out/%s" % (re.sub(r"[^A-Za-z0-9_.-]", "_", job), name)
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            fd = os.open(str(self.path), os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        except FileExistsError:
            raise TextRefused("the text file already exists: %s" % self.path)
        except OSError as exc:
            raise TextRefused("the text file could not be created: %s (%s)" % (self.path, describe(exc)))
        self._fh = os.fdopen(fd, "wb")

    def _put(self, data):
        _writing()
        try:
            self._fh.write(data)
        except OSError as exc:
            fail("the text file could not be written: %s (%s)" % (self.path, describe(exc)), text_file=str(self.path))
        finally:
            _written()

    def _room(self, size):
        """Whether `size` more bytes fit under the cap; the first that does not closes the file to every later record."""
        if self.capped or size > TEXTING["left"]:
            self.capped = True
            return False
        TEXTING["left"] -= size
        return True

    def add(self, row):
        if self._fh is None:
            return
        data = json.dumps(row, ensure_ascii=False, default=str).encode("utf-8", "backslashreplace") + b"\n"
        if not self._room(len(data)):
            self.not_written += 1
            return
        self.written += 1
        self._put(data)

    def add_bytes_raw(self, data):
        """A piece of a source's own bytes, written as it came; the record it belongs to is counted by count_record."""
        if self._fh is None:
            return
        if self._room(len(data)):
            self._open_piece = True
            self._put(data)
        elif self._open_piece:
            self.cut_record = True

    def count_record(self):
        if self._fh is not None:
            self._open_piece = False
            if self.capped:
                self.not_written += 1
            else:
                self.written += 1

    def add_bytes(self, data):
        """One record exactly as its source wrote it (a native export's line, newline included)."""
        if self._fh is None:
            return
        if not self._room(len(data)):
            self.not_written += 1
            return
        self.written += 1
        self._put(data)

    def close(self):
        if self._fh is not None:
            _writing()
            try:
                self._fh.flush()
                os.fsync(self._fh.fileno())
                self._fh.close()
                self._fh = None
            except OSError as exc:
                if STATE.get("stopping"):
                    self.close_error = describe(exc)    # the last word names it: one document, not an error document and then the last word
                    self._fh = None
                else:
                    fail("the text file could not be closed: %s (%s)" % (self.path, describe(exc)), text_file=str(self.path))
            finally:
                _written()

    def summary(self, preview=False):
        """What the answer says about text. `preview` is true when the answer itself carries it (preview_text)."""
        shown = {"answer_contains_text_that_may_hold_secrets": bool(preview)}
        if not self.enabled:
            hint = ("No text of any record is in a file." if not preview else
                    "The answer's records carry their text (preview); no file of it was written, and the paging file, if there is one, holds none.")
            return {"requested": False, "written": 0, "file": None, "contains_text_that_may_hold_secrets": False, **shown,
                    "hint": hint + " %s: true, in a job run with secret_output: true, keeps the whole of each record in a private file under $OUT." % self.flag}
        result = {"requested": True, "written": self.written, "file": self.shown,
                  "contains_text_that_may_hold_secrets": self.written > 0, **shown, "format": self.what}
        if self.not_written or self.capped:
            result["not_written"] = self.not_written
            result["not_written_why"] = ("the text file of one call holds at most %d bytes: the first %d records are in it, in order; the %d after them are "
                                         "counted and are in the evidence at the file and line each record names%s"
                                         % (MAX_TEXT_BYTES, self.written, self.not_written,
                                            "; the last record in the file may be cut short" if self.cut_record else ""))
        return result


def capped_why(pages, text=None):
    """The sentence for an answer that is partial because a cap was reached (the paging files' or the text file's), or None. `pages` is
    the answer's `pages` dictionary; `text` the TextFile."""
    cut = ["%d of %s" % (page["not_written"], name) for name, page in pages.items() if page.get("not_written")]
    held = []
    if cut:
        held.append("the paging files reached their cap of %d bytes: %s row(s) are counted and are not in a paging file (see not_written in `pages`)"
                    % (MAX_PAGING_BYTES, ", ".join(cut)))
    if text is not None and (text.not_written or text.capped):
        held.append("the text file reached its cap of %d bytes: %d record(s) are counted and are not in it (see not_written in `text`)"
                    % (MAX_TEXT_BYTES, text.not_written))
    if not held:
        return None
    return "; ".join(held) + "; each is in the evidence at the file and line it names"


INLINE_LIST = 200       # items of any list that grows with the evidence (files, homes, errors, links) kept inline in the answer


class Listed(list):
    """A list of the answer that grows with the evidence (one item per file, home, link or error): its first INLINE_LIST items are the list, and
    every item, those too, is kept in a paging file that the answer names under pages.<key> (`page.total` is how many there were; `settle()`
    finishes the file and returns the page's entry for the answer's `pages`)."""

    def __init__(self, key):
        super().__init__()
        self.page = LosslessPage(TOOL, key, INLINE_LIST)

    def append(self, item):
        self.page.add(item)
        if len(self) < INLINE_LIST:
            super().append(item)

    def settle(self):
        return self.page.finish()
# END LINUX PARTS


TRADITIONAL = re.compile(
    r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+(?P<proc>[^\s:\[]+)(?:\[(?P<pid>\d{1,10})\])?:\s*(?P<msg>.*)$")
ISO = re.compile(
    r"^(?P<stamp>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[+-]\d{2}:?\d{2}|Z)?)\s+"
    r"(?P<host>\S+)\s+(?P<proc>[^\s:\[]+)(?:\[(?P<pid>\d{1,10})\])?:\s*(?P<msg>.*)$")
ISO_PARTS = re.compile(
    r"^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?(Z|[+-]\d{2}:?\d{2})?$")

# The ssh key that follows "ssh2:" in an acceptance: "TYPE FINGERPRINT", or for a certificate
# "TYPE-CERT FINGERPRINT ID <key id> (serial N) CA TYPE FINGERPRINT".
KEY_CERT = re.compile(
    r"^(?P<keytype>\S+)\s+(?P<fingerprint>\S+)\s+ID\s(?P<cert_id>.*)\s\(serial\s(?P<cert_serial>\d{1,20})\)\s"
    r"CA\s(?P<ca_keytype>\S+)\s(?P<ca_fingerprint>\S+)\s*$")
KEY_PLAIN = re.compile(r"^(?P<keytype>\S+)\s+(?P<fingerprint>\S+)\s*$")

# Explicit variants, one per message form. Fields are named for what the line says; a value that is not an
# address is never a `source`.
RULES = [
    ("ssh_accepted", re.compile(
        r"^Accepted (?P<method>\S+) for (?P<user>.+?) from (?P<source>\S+) port (?P<port>\d+)(?: ssh2)?"
        r"(?::\s*(?P<key>.*))?")),
    # A name typed at a prompt is read from its position in the line, never from its shape. Where sshd says the account does not
    # exist (invalid user, illegal user) the name is everything between those words and the LAST " from <address> port <n>" (a
    # name can hold spaces, and can hold "from x port 1" too); the source and the port are what follows that last one.
    ("ssh_failed", re.compile(
        r"^Failed (?P<method>\S+) for (?P<invalid>(?:invalid|illegal) user )(?P<user>.+) from (?P<source>\S+) "
        r"port (?P<port>\d+)(?: ssh2)?(?::\s*(?P<key>.*))?")),
    ("ssh_failed", re.compile(
        r"^Failed (?P<method>\S+) for (?!(?:invalid|illegal) user )(?P<user>.+?) from (?P<source>\S+) "
        r"port (?P<port>\d+)(?: ssh2)?(?::\s*(?P<key>.*))?")),
    ("ssh_invalid_user", re.compile(r"^(?:Invalid|Illegal) user (?P<user>.*) from (?P<source>\S+)(?: port (?P<port>\d+))?")),
    ("ssh_disconnect", re.compile(
        r"^Received disconnect from (?P<source>\S+) port (?P<port>\d+):(?P<disconnect_code>\d{1,6}):\s*(?P<reason>.*)$")),
    # sshd always writes the port, and after it only a bracketed stage such as [preauth]. For an invalid user anything else is not
    # that form: the whole of what follows the words is the typed name (a name can hold " x port 1"), and no source is read from it.
    ("ssh_disconnect", re.compile(
        r"^Disconnected from (?P<role>invalid user) (?P<user>.*) (?P<source>\S+) port (?P<port>\d+)(?P<stage>(?: \[[^\]]*\])?)$")),
    ("ssh_disconnect", re.compile(r"^Disconnected from (?P<role>invalid user) (?P<user>.* \S+)$")),
    ("ssh_disconnect", re.compile(
        r"^Disconnected from (?P<role>authenticating user|user) (?P<user>.*) (?P<source>\S+) port (?P<port>\d+)(?P<stage>.*)$")),
    ("ssh_disconnect", re.compile(
        r"^Disconnected from (?P<role>authenticating user|user) (?P<user>.*) (?P<source>\S+)$")),
    ("ssh_disconnect", re.compile(
        r"^Disconnected from (?!(?:authenticating user|invalid user|user) )(?P<source>\S+)(?: port (?P<port>\d+))?(?P<stage>.*)$")),
    ("key_observed_authentication", re.compile(
        r"^Accepted key (?P<keytype>\S+) (?P<fingerprint>\S+)"
        r"(?: found at (?P<authorized_keys_file>.+?):(?P<authorized_keys_line>\d+))?")),
    ("sudo", re.compile(
        r"^\s*(?P<user>\S+)\s*:\s*TTY=(?P<tty>\S*)\s*;\s*PWD=(?P<pwd>\S*)\s*;\s*USER=(?P<target>\S+)\s*;\s*COMMAND=(?P<command>.*)$")),
    ("sudo_failed", re.compile(
        r"^\s*(?P<user>\S+)\s*:\s*(?:\d+ incorrect password attempts?|user NOT in sudoers|command not allowed)")),
    ("su", re.compile(r"^(?:\(to (?P<target>\S+)\) (?P<user>\S+)(?: on (?P<tty>\S+))?|"
                      r"Successful su for (?P<target2>\S+) by (?P<user2>\S+))")),
    ("su_failed", re.compile(r"^FAILED su for (?P<target>\S+) by (?P<user>\S+)")),
    ("session_opened", re.compile(
        r"^pam_unix\((?P<pam_service>[^:)]*):session\): session opened for user (?P<user>[^\s(]+)"
        r"(?:\(uid=(?P<uid>-?\d+)\))?(?: by (?P<by>[^\s(]*)(?:\(uid=(?P<by_uid>-?\d+)\))?)?")),
    ("session_closed", re.compile(
        r"^pam_unix\((?P<pam_service>[^:)]*):session\): session closed for user (?P<user>[^\s(]+)(?:\(uid=(?P<uid>-?\d+)\))?")),
    ("auth_failure", re.compile(r"^pam_unix\((?P<pam_service>[^:)]*):auth\): authentication failure;(?P<kv>.*)$")),
    ("account_added", re.compile(
        r"^new (?P<what>user|group): name=(?P<name>[^,]+)(?:, UID=(?P<uid>\d+))?(?:, GID=(?P<gid>\d+))?"
        r"(?:, home=(?P<home>[^,]*))?(?:, shell=(?P<shell>[^,]*))?")),
    ("account_changed", re.compile(
        r"^(?:pam_unix\([^)]*:chauthtok\): )?(?:changed password|password changed) for (?P<user>\S+)")),
]
KINDS = sorted({k for k, _ in RULES} | {"other"})
INT_FIELDS = ("port", "uid", "by_uid", "gid", "cert_serial", "authorized_keys_line", "disconnect_code")
# The key=value pairs of a pam_unix authentication failure that become fields. Any other key in the line is the
# line's own text (a typed user name can contain "key=value"), and a key can never overwrite a locator field.
PAM_KEYS = ("logname", "uid", "euid", "tty", "ruser", "rhost", "user")
PAM_USER = re.compile(r"(?:^|\s)user=")
PAM_RUSER = re.compile(r"(?:^|\s)ruser=")


def pam_rhost_last(rest):
    """(where the whitespace before it begins, its value) for an `rhost=<value>` that is the last word of `rest`, else None; the value may be
    empty. It is what `\\s*(?:^|\\s)rhost=(\\S*)\\s*$` found, in one pass from the end: that expression is tried at every offset, and in a
    64 KiB run of spaces each try ran to the end of the run, which cost the square of the length (a line of 65,000 bytes took a minute)."""
    body = rest.rstrip()
    start = len(body)
    while start > 0 and not body[start - 1].isspace():
        start -= 1
    if not body.startswith("rhost=", start):
        return None
    gap = start
    while gap > 0 and body[gap - 1].isspace():
        gap -= 1
    return gap, body[start + len("rhost="):]


# Fields a line's text can never set: they are the tool's own.
RESERVED = {"user_bytes", "user_withheld", "id", "parser", "file", "line", "byte_offset", "time", "time_raw", "time_zone", "time_utc", "year", "host",
            "process", "pid", "kind", "reordered", "time_error", "text_bytes", "command_bytes", "raw", "line_text", "year_assumed"}
# What is the text of a line and not a field of it: held back from the answer, kept in the text file.
TEXT_FIELDS = ("raw", "command")


def address_ok(text):
    try:
        ipaddress.ip_address(text.split("%", 1)[0])
        return True
    except ValueError:
        return False


def finish(kind, fields):
    """(fields, typed): the fields a line gives, and the names among them that are text someone typed at a prompt,
    where the log itself says there is no such account (an invalid user) or the form does not say (a PAM `user=`)."""
    typed = []
    if kind in ("ssh_accepted", "ssh_failed"):
        key = fields.pop("key", None)
        if key:
            found = KEY_CERT.match(key) or KEY_PLAIN.match(key)
            if found:
                fields.update({k: v for k, v in found.groupdict().items() if v})
            else:
                fields["key_text_unparsed"] = True
    if kind == "ssh_failed":
        if fields.pop("invalid", None):
            fields["invalid_user"] = True
            typed.append("user")
    if kind == "ssh_invalid_user":
        typed.append("user")
    if kind == "ssh_disconnect":
        role = fields.pop("role", None)
        if role:
            fields["user_role"] = role
            if role == "invalid user":
                typed.append("user")
        stage = (fields.pop("stage", "") or "").strip()
        if stage:
            fields["stage"] = stage
    if kind == "auth_failure":
        # pam_unix writes `user=` last, and the rest of the line is the name (a name can hold spaces, and "tty=x" or "rhost=x"):
        # it is split off first, by position. `ruser=` (the remote user a service such as dovecot, vsftpd or exim passes: the
        # login name typed there) is the text between `ruser=` and the last ` rhost=`; the key=value pairs before `ruser=`
        # are read first-one-wins. Nothing that follows `ruser=` or `user=` can set another field.
        text = fields.pop("kv", "") or ""
        head = text
        found = PAM_USER.search(text)
        if found:
            head = text[:found.start()]
            name = text[found.end():]
            if name.strip():
                fields["user"] = name
        pre = head
        found = PAM_RUSER.search(head)
        if found:
            pre = head[:found.start()]
            rest = head[found.end():]
            tail = pam_rhost_last(rest)
            ruser = rest[:tail[0]] if tail else rest
            if tail and tail[1]:
                fields["rhost"] = tail[1]
            if ruser.strip():
                fields["ruser"] = ruser.strip()
        for token in pre.split():
            key, eq, value = token.partition("=")
            if not eq or value == "" or key not in PAM_KEYS or key in ("user", "ruser") or key in fields:
                continue
            fields[key] = value
        if "rhost" in fields:
            fields["source"] = fields.pop("rhost")
        for typed_key in ("user", "ruser"):
            if typed_key in fields:
                typed.append(typed_key)
    if kind == "su":
        for plain in ("target", "user"):
            if plain + "2" in fields:
                fields[plain] = fields.pop(plain + "2")
    if "source" in fields and not address_ok(fields["source"]):
        fields["source_unvalidated"] = fields.pop("source")
    for key in INT_FIELDS:
        if key in fields:
            try:
                fields[key] = int(fields[key])
            except ValueError:
                fields.pop(key)
    return {k: v for k, v in fields.items() if k not in RESERVED}, typed


def classify(message):
    for kind, pattern in RULES:
        found = pattern.match(message)
        if found:
            fields = {k: v for k, v in found.groupdict().items() if v not in (None, "")}
            return (kind,) + finish(kind, fields)
    return "other", {}, []


# --- the files and their order ---------------------------------------------------------------------

def rotation_basis(path):
    """(rank, key, basis): oldest first. A number is a rotation count (a higher one is older), a date is
    that day, and the live file is the newest. Anything else is ordered by name, and said so."""
    name = os.path.basename(path)
    found = re.search(r"[-.]((?:19|20)\d\d(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01]))(?:\.gz)?$", name)
    if found:
        return 1, int(found.group(1)), "date suffix"
    found = re.search(r"\.(\d{1,6})(?:\.gz)?$", name)
    if found:
        return 1, -int(found.group(1)), "numeric rotation suffix"
    if re.fullmatch(r"(?:auth\.log|secure)", name):
        return 2, 0, "current file"
    return 0, 0, "name only"


class FileState:
    def __init__(self, path):
        self.path = path
        self.errors = []
        self.compression = "none"
        self.lines_before_error = 0


def open_binary(path, state):
    raw = open(path, "rb")
    magic = raw.read(2)
    raw.seek(0)
    if magic == b"\x1f\x8b":
        state.compression = "gzip"
        return gzip.GzipFile(fileobj=raw)
    raw.seek(0)
    head = raw.read(6)
    raw.seek(0)
    for name, signature in (("bzip2", b"BZh"), ("xz", b"\xfd7zXZ\x00"), ("zstd", b"\x28\xb5\x2f\xfd")):
        if head.startswith(signature):
            raw.close()
            raise OSError("this file is %s-compressed: only gzip is read here; decompress a copy with the tool that made it and read that" % name)
    return raw


def physical_lines(path, state, expanded_cap=None, deadline=None):
    """(line number, byte offset, bytes or None when over MAX_LINE, bytes in the line) for each physical line.

    A read or a decompression error ends the iteration, is recorded in state.errors with where it
    happened, and is not raised: what was read before it is kept. The offset is into the stream as it
    comes out (the decompressed one for a gzip file); a gzip stream that expands past `expanded_cap`
    bytes ends there as a recorded error, so a compression bomb costs a bounded amount of work. The clock is read inside
    the loop that skips a line over MAX_LINE (every 64 pieces), so a file with no newline for gigabytes ends at `deadline`
    too: Overtime is raised from here."""
    try:
        handle = open_binary(path, state)
    except OSError as exc:
        state.errors.append({"file": path, "error": describe(exc), "line": 0, "byte_offset": 0})
        return
    offset, number = 0, 0
    try:
        with handle:
            while True:
                chunk = handle.readline(MAX_LINE + 1)
                if not chunk:
                    return
                length = len(chunk)
                if expanded_cap is not None and state.compression == "gzip" and offset + length > expanded_cap:
                    state.errors.append({"file": path, "error": "the decompressed stream passed max_expanded_bytes (%d): not read past it" % expanded_cap,
                                         "line": number, "byte_offset": offset})
                    return
                if length > MAX_LINE and not chunk.endswith(b"\n"):
                    # Read on to the end of the line without holding it.
                    pieces = 0
                    while True:
                        more = handle.readline(MAX_LINE + 1)
                        length += len(more)
                        pieces += 1
                        if deadline is not None and (pieces & 63) == 0 and time.monotonic() > deadline:
                            raise Overtime()
                        if expanded_cap is not None and state.compression == "gzip" and offset + length > expanded_cap:
                            state.errors.append({"file": path, "error": "the decompressed stream passed max_expanded_bytes (%d): not read past it" % expanded_cap,
                                                 "line": number + 1, "byte_offset": offset})
                            return
                        if not more or more.endswith(b"\n"):
                            break
                    number += 1
                    yield number, offset, None, length
                    offset += length
                    continue
                number += 1
                yield number, offset, chunk, length
                offset += length
    except (OSError, EOFError, zlib.error) as exc:
        state.errors.append({"file": path, "error": describe(exc), "line": number, "byte_offset": offset})


# --- months, years, zones ---------------------------------------------------------------------------

FIRST, SAME, FORWARD, ROLLOVER, REORDERED = range(5)


def circular(a, b):
    return min((a - b) % 12, (b - a) % 12)


MONTH_NAMES = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")


def packed_parts(packed):
    """(month, day, hour, minute, second) of a date packed as ((((month * 32 + day) * 24 + h) * 60 + m) * 61 + s)."""
    v, sec = divmod(packed, 61)
    v, minute = divmod(v, 60)
    v, hour = divmod(v, 24)
    month, day = divmod(v, 32)
    return month, day, hour, minute, sec


def stamp_of(packed):
    """A packed date as a traditional syslog stamp reads."""
    month, day, hour, minute, sec = packed_parts(packed)
    return "%s %2d %02d:%02d:%02d" % (MONTH_NAMES[month - 1], day, hour, minute, sec)


def step_days(before, after, year_end):
    """Whole days from one packed date to the next, as the dating rule reads the step: the same year, or the next one
    when the step crosses a year end. Year 2000 is the leap one, so every date that exists is a date here; a 29 February
    that falls in the following year is read as the 28th."""
    m1, d1, h1, i1, s1 = packed_parts(before)
    m2, d2, h2, i2, s2 = packed_parts(after)
    start = datetime.datetime(2000, m1, d1, h1, i1, min(s1, 59))
    try:
        end = datetime.datetime(2001 if year_end else 2000, m2, d2, h2, i2, min(s2, 59))
    except ValueError:
        end = datetime.datetime(2001 if year_end else 2000, m2, 28, h2, i2, min(s2, 59))
    return (end - start).days


class MonthScan:
    """Pass one: how each dated line's month relates to the lines before and after it, found as the lines go by, so that
    a dated line costs one byte (its class). `push` takes a line's month, its packed date and its line number; `finish`
    settles the last one. Afterwards: `classes` (a bytearray of FIRST, SAME, FORWARD, ROLLOVER or REORDERED), `rollovers`,
    `rollover_lines` (the line numbers of the first few), `reordered`, `last_ok` (the packed date and line number of the
    last line in order) and the forward steps longer than STEP_DAYS days: `step_count`, `steps` (the first STEP_INLINE) and
    `last_step_line` (the line that ended the last one); each step is also given to `on_step`, which keeps the whole list.

    The rule. A month that goes up is the log moving on, however long the gap (a machine that was off for eight months
    wrote January and then September of one year): the year does not change, and a step longer than STEP_DAYS is reported
    so that nobody takes it for a certainty. A month that goes down is a year end when it comes within six months after the
    last one (Dec to Jan), and a step back in time otherwise. A line that the next line contradicts is out of order
    whichever way it points: one that is further from the last in-order month than the line after it is (January, March,
    January: the March line is the stray; January, December, January: the December one). The last line has no next line,
    so a downward step of more than six months is all it can show. A line out of order does not move the place the next
    one is compared with. Only lines whose date and clock exist are given to this."""

    def __init__(self, on_step=None):
        self.classes = bytearray()
        self.rollovers = 0
        self.rollover_lines = []
        self.reordered = 0
        self.last_ok = None
        self.step_count = 0
        self.steps = []
        self.last_step_line = None
        self._on_step = on_step
        self._prev = None
        self._held = None

    def push(self, month, packed, number):
        held, self._held = self._held, (month, packed, number)
        if held is not None:
            self._settle(held, month)

    def finish(self):
        if self._held is not None:
            held, self._held = self._held, None
            self._settle(held, None)

    def _settle(self, held, nx):
        m, packed, number = held
        prev = self._prev
        if prev is None:
            cls = FIRST
        elif m == prev:
            cls = SAME
        else:
            if nx is not None:
                stray = nx != m and circular(prev, nx) < circular(prev, m)
            else:
                stray = m < prev and (m - prev) % 12 > 6
            if stray or (m < prev and (m - prev) % 12 > 6):
                cls = REORDERED
            else:
                cls = ROLLOVER if m < prev else FORWARD
        self.classes.append(cls)
        if cls == REORDERED:
            self.reordered += 1
            return
        if cls == ROLLOVER:
            self.rollovers += 1
            if len(self.rollover_lines) < 20:
                self.rollover_lines.append(number)
        if cls in (FORWARD, ROLLOVER):
            days = step_days(self.last_ok[0], packed, cls == ROLLOVER)
            if days > STEP_DAYS:
                step = {"line": number, "from": stamp_of(self.last_ok[0]), "to": stamp_of(packed), "days": days,
                        "from_line": self.last_ok[1]}
                self.step_count += 1
                self.last_step_line = number
                if len(self.steps) < STEP_INLINE:
                    self.steps.append(step)
                if self._on_step is not None:
                    self._on_step(step)
        self._prev = m
        self.last_ok = (packed, number)


def valid_clock(day_time):
    h, m, s = (int(x) for x in day_time.split(":"))
    return h < 24 and m < 60 and s < 61


def anchor_year(last, mtime):
    """The year of the last in-order line: the latest year in which that date is no later than the file's
    modification time plus the 26 hours the log's unknown zone allows."""
    limit = mtime + ZONE_SLACK
    year = limit.year
    for _ in range(8):
        try:
            when = datetime.datetime(year, *last)
        except ValueError:
            year -= 1
            continue
        if when <= limit:
            return year
        year -= 1
    return None


def traditional_time(year, month, day, clock):
    try:
        h, m, s = (int(x) for x in clock.split(":"))
        return datetime.datetime(year, month, day, h, m, min(s, 59)), None
    except ValueError:
        return None, "no such date or time: month %d day %d %s in %d" % (month, day, clock, year)


def iso_time(stamp):
    """(time, time_utc, time_zone, error, notes) for an RFC 3339 stamp, its fraction kept. `time` is the clock reading as
    written, with no zone designator; `time_utc` is the same instant in UTC and exists only where the stamp carries
    its zone."""
    found = ISO_PARTS.match(stamp)
    if not found:
        return None, None, "unknown", "stamp does not match RFC 3339", []
    y, mo, d, h, mi, s, frac, zone = found.groups()
    micro = int((frac or "0")[:6].ljust(6, "0"))
    note = []
    if frac and len(frac) > 6:
        note.append("the fraction has %d digits and is kept to 6" % len(frac))
    second = int(s)
    if second == 60:
        second = 59
        note.append("second 60 (a leap second) is shown as 59")
    try:
        naive = datetime.datetime(int(y), int(mo), int(d), int(h), int(mi), second, micro)
    except ValueError:
        return None, None, zone or "unknown", "no such date or time in the stamp", note
    shown = naive.isoformat()
    if zone is None:
        return shown, None, "unknown", None, note
    if zone == "Z":
        offset, kept = datetime.timedelta(0), "Z"
    else:
        digits = zone[1:].replace(":", "")
        hours, minutes = int(digits[:2]), int(digits[2:])
        if hours > 23 or minutes > 59:
            return shown, None, zone, "the zone offset %s is not a valid offset" % zone, note
        offset = datetime.timedelta(hours=hours, minutes=minutes)
        offset = offset if zone[0] == "+" else -offset
        kept = "%s%02d:%02d" % (zone[0], hours, minutes)
    try:
        utc = (naive - offset).isoformat() + "Z"
    except OverflowError:
        return shown, None, kept, "the stamp in UTC is outside the range of a date", note
    return shown, utc, kept, None, note


# --- the run -----------------------------------------------------------------------------------------

def short_fields(fields):
    """The fields as the answer shows them: a long free-text value is cut at 256 characters and its whole length said.
    The whole is in the text file (write_text) and in the evidence at the record's locator."""
    shown, cut = {}, {}
    for key, value in fields.items():
        value, whole = bound(value, 256)
        shown[key] = value
        if whole is not None:
            cut[key] = whole
    if cut:
        shown["truncated_fields"] = cut
    return shown


def shown_text(row):
    """What `contains` may match outside a job: the fields the answer shows, and nothing it withholds."""
    return " ".join(str(v) for k, v in row.items() if v is not None and k not in ("id", "parser", "byte_offset", "text_bytes"))


class Overtime(Exception):
    pass


# BEGIN LINUX IMAGE
# ---- A disk image given where this tool reads a file or an extracted root (the same in every such tool of this pack) ----

# What linux_triage takes as an image: these first bytes, or one of its names with a boot sector's signature at 510.
IMAGE_MAGIC = ((0, b"EVF\x09\x0d\x0a\xff\x00"), (0, b"EVF2\x0d\x0a\x81\x00"), (0, b"vhdxfile"), (0, b"conectix"), (0, b"KDMV"),
               (0, b"QFI\xfb"))
IMAGE_SUFFIXES = (".e01", ".ex01", ".dd", ".img", ".raw", ".vhd", ".vhdx", ".vmdk", ".qcow2")
IMAGE_ROUTES = ("this tool reads the files of an extracted file system, not a disk image. For a Linux image: the catalogue's "
                "linux-target artefacts (catalog/README.md says where) hold what dissect.target parsed from it, LVM included; "
                "linux_triage reads the image itself as a job; and to give this tool the files, extract them first in a job, a "
                "directory at a time, with target-fs -q <image> cp <dir> -o \"$OUT/root<dir>\" (for example /etc, /var/log, "
                "/var/spool/cron, /home and /root), then pass the extracted path under store/jobs/<id>/out/root/. The copies "
                "carry the time of extraction as their modification time, and links are not copied as links.")


def refuse_disk_image(path, key):
    """A regular file whose first bytes, or whose name and boot-sector signature, say disk image is refused with the routes
    that read one; anything else goes on to this tool's own checks. It reads 512 bytes and nothing else. A path the system
    cannot take (a NUL in it, a lone surrogate) is left to those checks too, which answer it in JSON."""
    try:
        if os.path.islink(path) or not stat.S_ISREG(os.stat(path).st_mode):
            return
        # Without blocking: a regular file whose read waits (/proc/kmsg, read as root) answers at once, and is no image.
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0))
        try:
            head = os.read(fd, 512)
        finally:
            os.close(fd)
    except (OSError, ValueError):
        return
    named = path.lower().endswith(IMAGE_SUFFIXES)
    if any(head[o:o + len(m)] == m for o, m in IMAGE_MAGIC) or (named and head[510:512] == b"\x55\xaa"):
        fail("%s is a disk image: %s" % (key, IMAGE_ROUTES), **{key: path})
# END LINUX IMAGE


def gzip_header_time(path):
    """(present, epoch seconds or None) of a gzip file's header MTIME (RFC 1952: bytes 4 to 7, little-endian; 0 means the
    compressor recorded none). (False, None) for a file that is not gzip or cannot be read."""
    try:
        with open(path, "rb") as handle:
            head = handle.read(10)
    except OSError:
        return False, None
    if len(head) < 10 or head[:2] != b"\x1f\x8b":
        return False, None
    value = int.from_bytes(head[4:8], "little")
    return True, (value or None)


def want_years(args, targets):
    """The `years` argument as {file path: [[from_line, year, counters], ...]}, in the order given, which must be ascending
    by line within a file. Every refusal is JSON and happens before anything is read."""
    given = args.get("years")
    if given is None:
        return {}
    if not isinstance(given, list):
        fail("years must be a list of {file, from_line, year}")
    if len(given) > MAX_YEARS:
        fail("years has %d entries: at most %d are read" % (len(given), MAX_YEARS))
    by_name = {}
    for target in targets:
        by_name.setdefault(os.path.normpath(target), target)
    ranges, last_line = {}, {}
    for index, entry in enumerate(given):
        where = "years[%d]" % index
        if not isinstance(entry, dict) or set(entry) != {"file", "from_line", "year"}:
            fail("%s must be an object with exactly file, from_line and year" % where)
        name, line, year = entry["file"], entry["from_line"], entry["year"]
        if not isinstance(name, str) or not name:
            fail("%s: file must be a string, one of the call's files" % where)
        target = name if name in targets else by_name.get(os.path.normpath(name))
        if target is None:
            fail("%s: %s is not one of the files of this call" % (where, name if len(name) <= 200 else name[:200] + "..."),
                 files=sorted(targets)[:50])
        if isinstance(line, bool) or not isinstance(line, int) or not 1 <= line <= 1 << 50:
            fail("%s: from_line must be a whole number of 1 or more" % where)
        if isinstance(year, bool) or not isinstance(year, int) or not YEAR_MIN <= year <= YEAR_MAX:
            fail("%s: year must be a whole year between %d and %d" % (where, YEAR_MIN, YEAR_MAX))
        if target in last_line and line <= last_line[target]:
            fail("%s: the ranges of %s must be ascending by from_line and may not overlap (from_line %d does not come after %d)"
                 % (where, target, line, last_line[target]))
        last_line[target] = line
        ranges.setdefault(target, []).append([line, year, {"lines": 0, "first_dated": None}])
    return ranges


def main():
    args = read_args()
    path = want_str(args, "path", "path is required: an auth.log or secure file, or a directory holding them")
    if os.path.islink(path):
        fail("refusing a symlink: pass the log file or directory inside the evidence", path=path,
             target=os.readlink(path))
    refuse_disk_image(path, "path")
    limit = want_limit(args)
    write_text, preview_text = want_flag(args, "write_text"), want_flag(args, "preview_text")
    if preview_text:
        require_job("preview_text")
    year_arg = args.get("year")
    if year_arg is not None and (isinstance(year_arg, bool) or not isinstance(year_arg, int) or not 1970 <= year_arg <= 2200):
        fail("year must be a whole year between 1970 and 2200")
    wanted = set(want_str_list(args, "kinds"))
    if "key_added" in wanted:
        fail("key_added was renamed key_observed_authentication: an `Accepted key` line is sshd matching a "
             "login against an authorized_keys entry, not a key being installed", known=KINDS)
    unknown = sorted(wanted - set(KINDS))
    if unknown:
        fail("unknown kinds: %s" % ", ".join(unknown), known=KINDS)
    needle = (want_str(args, "contains") or "").lower()
    expand_cap = args.get("max_expanded_bytes", DEFAULT_EXPANDED)
    if isinstance(expand_cap, bool) or not isinstance(expand_cap, int) or expand_cap < 1:
        fail("max_expanded_bytes must be a positive integer")
    seconds = want_seconds(args, "max_seconds", DEFAULT_SECONDS, MAX_SECONDS)
    deadline = time.monotonic() + seconds

    walk_errors, skipped_symlinks, skipped_special = Listed("walk_errors"), Listed("skipped_symlinks"), Listed("skipped_special")
    targets = []

    def regular(candidate):
        try:
            if os.path.islink(candidate):
                skipped_symlinks.append({"file": candidate, "target": os.readlink(candidate)})
                return False
            if not stat.S_ISREG(os.lstat(candidate).st_mode):
                skipped_special.append({"file": candidate, "reason": "not a regular file (a pipe, a socket or a device): never opened"})
                return False
        except OSError as exc:
            walk_errors.append({"path": candidate, "error": describe(exc)})
            return False
        return True

    try:
        is_dir = os.path.isdir(path)
        exists_ = os.path.lexists(path)
    except OSError as exc:
        fail("the path cannot be examined", path=path, reason=describe(exc))
    if is_dir:
        def on_error(exc):
            walk_errors.append({"path": getattr(exc, "filename", None), "error": describe(exc)})
        walk_stopped = False
        for root, dirs, names in os.walk(path, onerror=on_error):
            # A directory tree of millions of entries (a whole file system passed by mistake, or one directory of millions of files) is
            # looked through on the clock: it is read every 256 entries, and at the end the answer says where the walk stopped.
            ndirs = len(dirs)
            for step, name in enumerate(itertools.chain(list(dirs), names)):
                if (step & 255) == 0 and time.monotonic() > deadline:
                    walk_stopped = True
                    break
                if step < ndirs:
                    if os.path.islink(os.path.join(root, name)):
                        skipped_symlinks.append({"file": os.path.join(root, name), "target": os.readlink(os.path.join(root, name))})
                        dirs.remove(name)
                elif re.match(r"^(auth\.log|secure)", name):
                    candidate = os.path.join(root, name)
                    if regular(candidate):
                        targets.append(candidate)
            if walk_stopped:
                walk_errors.append({"path": root, "error": "max_seconds (%s) passed while looking for log files: the walk stopped here, and the places after it were not looked in" % seconds})
                break
    elif exists_:
        try:
            special = not stat.S_ISREG(os.lstat(path).st_mode)
        except OSError as exc:
            fail("the path cannot be examined", path=path, reason=describe(exc))
        if special:
            fail("not a regular file or a directory: a pipe, a socket or a device is never opened", path=path)
        targets = [path]
    else:
        fail("no such file or directory", path=path)
    if not targets:
        fail("no auth.log or secure file found there", path=path, skipped_symlinks=skipped_symlinks,
             skipped_special=skipped_special, walk_errors=walk_errors,
             pages={k: v.page.finish() for k, v in (("skipped_symlinks", skipped_symlinks), ("skipped_special", skipped_special), ("walk_errors", walk_errors))})
    ranked = sorted(((rotation_basis(t), t) for t in targets), key=lambda row: (row[0][0], row[0][1], row[1]))
    # Whether every file of the call has one modification time to within seconds (a copy made in one go): known before the files are read.
    shared_mtime = False
    if len(targets) > 1:
        lowest = highest = None
        shared_mtime = True
        for number, candidate in enumerate(targets):
            if (number & 1023) == 0 and time.monotonic() > deadline:
                shared_mtime = False
                break
            try:
                stamp = os.path.getmtime(candidate)
            except (OSError, ValueError, OverflowError):
                shared_mtime = False
                break
            lowest = stamp if lowest is None else min(lowest, stamp)
            highest = stamp if highest is None else max(highest, stamp)
        shared_mtime = shared_mtime and highest - lowest <= SAME_MTIME_SECONDS
    schemes = {basis for (rank, _k, basis), _t in ranked if rank == 1}
    years_by_file = want_years(args, targets)

    try:
        text = TextFile(TEXT_NAME, write_text, "JSON Lines, mode 0600: the record's id, locator and fields as in the answer, "
                        "with `raw` (the message), `command` (a sudo command line), a typed `user` and `line_text` (the physical line)")
    except TextRefused as exc:
        fail(str(exc))
    STATE["text"] = text
    page = LosslessPage(TOOL, "records", limit)
    unparsed_page = LosslessPage(TOOL, "unparsed", limit)
    steps_page = LosslessPage(TOOL, "forward_steps", limit)
    preview_rows = []

    files, read_errors, by_kind = Listed("files"), Listed("read_errors"), {}
    overlaps, not_reached = Listed("cross_file_order_overlaps"), Listed("files_not_reached")
    counts = {"physical": 0, "blank": 0, "read": 0, "unparsed": 0, "time_errors": 0, "invalid_utf8": 0}
    seq = 0
    hit_deadline = False
    previous = {"path": None, "last_time": None}
    only_dead = [True]      # every file so far was partial and had no line (nothing could be read)

    def settle_file(f, mtime_ts, last_line):
        """What a file's modification time may be (a copy's), then the file joins the list; the order against the file before it is checked here."""
        why = []
        if last_line is not None and mtime_ts is not None:
            after = (datetime.datetime.fromtimestamp(mtime_ts, datetime.timezone.utc).replace(tzinfo=None) - last_line).total_seconds() / 86400
            if after > COPY_DAYS:
                why.append("the modification time is %d days after the last dated line (more than %d)" % (after, COPY_DAYS))
        if shared_mtime:
            why.append("every file of this call has the same modification time, to within %d seconds" % SAME_MTIME_SECONDS)
        if f["compression"] == "gzip":
            present, header = gzip_header_time(f["path"])
            f["gzip_header_time"] = None if not present or header is None else datetime.datetime.fromtimestamp(header, datetime.timezone.utc).replace(tzinfo=None).isoformat() + "Z"
            f["gzip_header_time_recorded"] = bool(present and header is not None)
            if present and header is not None and mtime_ts is not None:
                agree = abs(mtime_ts - header) <= GZ_AGREE_SECONDS
                f["gzip_header_agrees_with_modified"] = agree
                if not agree:
                    why.append("the gzip header time (%s) differs from the modification time by more than %d seconds" % (f["gzip_header_time"], GZ_AGREE_SECONDS))
            else:
                f["gzip_header_agrees_with_modified"] = None
        f["mtime_may_be_copy_time"] = bool(why)
        if why:
            f["mtime_may_be_copy_time_why"] = why
        if previous["last_time"] and f["first_time"] and f["first_time"] < previous["last_time"]:
            overlaps.append({"earlier": previous["path"], "later": f["path"], "earlier_last": previous["last_time"], "later_first": f["first_time"]})
        previous["path"], previous["last_time"] = f["path"], f["last_time"]
        only_dead[0] = only_dead[0] and f["partial"] and f["physical_lines"] == 0
        files.append(f)

    def tick(n):
        if n % 4096 == 0 and time.monotonic() > deadline:
            raise Overtime()

    for (rank, _key, basis), target in ranked:
        if not hit_deadline and time.monotonic() > deadline:
            hit_deadline = True         # the clock is read for every file: a directory of many files with no line in them ends here too
        if hit_deadline:
            not_reached.append(target)
            continue
        state = FileState(target)
        info = {"path": target, "order_basis": basis, "compression": "none", "size": None, "modified": None,
                "physical_lines": 0, "unparsed_lines": 0, "records": 0, "formats": {}, "year_basis": None,
                "first_year": None, "last_year": None, "rollovers": 0, "rollover_lines": [], "reordered_lines": 0,
                "first_time": None, "last_time": None, "partial": False}
        mtime_ts, anchor_when = None, None
        try:
            info["size"] = os.path.getsize(target)
            mtime_ts = os.path.getmtime(target)
            mtime = datetime.datetime.fromtimestamp(mtime_ts, datetime.timezone.utc).replace(tzinfo=None)
            info["modified"] = mtime.isoformat() + "Z"
        except (OSError, ValueError, OverflowError):
            mtime = None
            mtime_ts = None

        def note_step(step, target=target):
            steps_page.add({"file": target, **step})

        # Pass one: the class of every line whose date exists (one byte each, settled as the lines go by), the year ends,
        # the forward steps longer than STEP_DAYS, and the last line in order, so that the year of that line can be worked
        # back through the year ends the months show.
        scan = MonthScan(note_step)
        try:
            for n, (_n, _o, chunk, _l) in enumerate(physical_lines(target, state, expand_cap, deadline)):
                tick(n)
                if chunk is None:
                    continue
                found = TRADITIONAL.match(decode(chunk).rstrip("\r\n"))
                if not found or found.group("mon") not in MONTHS:
                    continue
                month, day = MONTHS[found.group("mon")], int(found.group("day"))
                try:
                    datetime.datetime(2000, month, day)
                    valid = valid_clock(found.group("time"))
                except ValueError:
                    valid = False
                if not valid:
                    continue            # a date that does not exist says nothing about which way the months run
                h, m, sec = (int(x) for x in found.group("time").split(":"))
                scan.push(month, (((month * 32 + day) * 24 + h) * 60 + m) * 61 + sec, _n)
            scan.finish()
        except Overtime:
            hit_deadline = True
            read_errors.append({"file": target, "error": "max_seconds (%s) passed while reading this file: it was not read further" % seconds, "line": None, "byte_offset": None})
            info["partial"] = True
            settle_file(info, mtime_ts, None)
            continue
        classes, rollovers = scan.classes, scan.rollovers
        info["rollovers"], info["rollover_lines"] = rollovers, scan.rollover_lines
        info["reordered_lines"] = scan.reordered
        last_valid = packed_parts(scan.last_ok[0]) if scan.last_ok else None
        anchor = anchor_year(last_valid, mtime) if mtime is not None and last_valid is not None else None
        mtime_basis = "file mtime (UTC, with 26 hours allowed for the log's unknown zone; on a copied tree it is the time of the copy)"
        if year_arg is not None:
            first_year, info["year_basis"] = year_arg, "argument"
            info["year_argument_spans_rollover"] = rollovers > 0
        elif mtime is not None and last_valid is not None:
            first_year = None if anchor is None else anchor - rollovers
            info["year_basis"] = mtime_basis
        else:
            first_year, info["year_basis"] = None, "none: no readable modification time or no dated line"
        ranges = years_by_file.get(target, [])
        if ranges:
            info["year_basis"] = ("years argument for the lines from line %s on (%d range%s); the other lines: %s"
                                  % (ranges[0][0], len(ranges), "" if len(ranges) == 1 else "s", info["year_basis"]))
        info["forward_steps"] = scan.steps
        info["forward_step_count"] = scan.step_count
        info["forward_step_days_over"] = STEP_DAYS
        info["year_assumed_before_line"] = scan.last_step_line
        info["year_anchor"] = None
        if scan.last_ok:
            info["year_anchor"] = {"line": scan.last_ok[1], "stamp": stamp_of(scan.last_ok[0]), "mtime": info["modified"],
                                   "year": anchor, "used_for_dating": year_arg is None}
            if anchor is not None:
                anchor_when = datetime.datetime(anchor, *last_valid[:4], min(last_valid[4], 59))
        # Pass two: the records.
        state = FileState(target)
        year, cursor, valid_index, range_at = first_year, None, 0, -1
        last_step_line = scan.last_step_line
        spans_rollover = False
        try:
            for number, offset, chunk, length in physical_lines(target, state, expand_cap, deadline):
                tick(number)
                counts["physical"] += 1
                info["physical_lines"] += 1
                if chunk is None:
                    counts["unparsed"] += 1
                    info["unparsed_lines"] += 1
                    row = {"file": target, "line": number, "byte_offset": offset, "bytes": length, "reason": "line longer than %d bytes: located, not parsed" % MAX_LINE}
                    unparsed_page.add(row)
                    text.add({"record_type": "unparsed", **row, "line_text": None})
                    continue
                if b"\xff" in chunk or not chunk.isascii():
                    try:
                        chunk.decode("utf-8")
                    except UnicodeDecodeError:
                        counts["invalid_utf8"] += 1
                line = decode(chunk)
                if line.endswith("\n"):
                    line = line[:-1]
                if line.endswith("\r"):
                    line = line[:-1]
                if not line.strip():
                    counts["blank"] += 1
                    continue
                counts["read"] += 1
                found = TRADITIONAL.match(line)
                iso = None if found else ISO.match(line)
                reason = None
                if found and found.group("mon") not in MONTHS:
                    reason, found = "unknown month %r: not placed in any year" % found.group("mon"), None
                elif not found and not iso:
                    reason = "not a syslog line"
                if reason:
                    counts["unparsed"] += 1
                    info["unparsed_lines"] += 1
                    row = {"file": target, "line": number, "byte_offset": offset, "bytes": length, "reason": reason}
                    unparsed_page.add(row)
                    text.add({"record_type": "unparsed", **row, "line_text": line})
                    continue
                parts = (found or iso).groupdict()
                time_fields, range_key = {}, None
                if found:
                    info["formats"]["traditional"] = info["formats"].get("traditional", 0) + 1
                    month, day = MONTHS[parts["mon"]], int(parts["day"])
                    try:
                        datetime.datetime(2000, month, day)
                        exists = valid_clock(parts["time"])
                    except ValueError:
                        exists = False
                    cls = None
                    if exists:
                        cls = classes[valid_index] if valid_index < len(classes) else SAME
                        valid_index += 1
                    reordered = cls == REORDERED
                    when, error, use, assumed = None, None, None, False
                    if cls == ROLLOVER and year is not None and year_arg is None:
                        year += 1       # the anchored year goes on through the year ends whichever year a range gives a line
                    while range_at + 1 < len(ranges) and ranges[range_at + 1][0] <= number:
                        range_at += 1
                    if range_at >= 0:
                        counters = ranges[range_at][2]
                        counters["lines"] += 1
                        if counters["first_dated"] is None:
                            counters["first_dated"] = number
                        elif cls == ROLLOVER:
                            spans_rollover = True
                        use = ranges[range_at][1]
                        when, error = traditional_time(use, month, day, parts["time"])
                    elif year_arg is not None:
                        use = year_arg
                        when, error = traditional_time(use, month, day, parts["time"])
                    else:
                        assumed = last_step_line is not None and number < last_step_line
                        if year is None:
                            error = "no year could be applied (%s)" % info["year_basis"]
                        elif not exists:
                            use = year
                            when, error = traditional_time(use, month, day, parts["time"])
                        elif reordered and cursor is not None:
                            # Out of order: the year that puts it nearest the lines around it.
                            best = None
                            for candidate in (year - 1, year, year + 1):
                                dt, _err = traditional_time(candidate, month, day, parts["time"])
                                if dt is not None and (best is None or abs(dt - cursor) < abs(best[0] - cursor)):
                                    best = (dt, candidate)
                            if best:
                                when, use = best
                            else:
                                error = "no such date or time: month %d day %d %s" % (month, day, parts["time"])
                        else:
                            use = year
                            when, error = traditional_time(use, month, day, parts["time"])
                    if when is not None and not reordered:
                        cursor = when
                        range_key = when.isoformat()
                        info["first_year"] = info["first_year"] or when.year
                        info["last_year"] = when.year
                    time_fields = {"time": when.isoformat() if when else None,
                                   "time_raw": line[:found.start("host")].rstrip(),
                                   "time_zone": "unknown", "time_utc": None, "year": use if when else None}
                    if assumed and when is not None:
                        time_fields["year_assumed"] = True
                    if error:
                        time_fields["time_error"] = error
                    if parts["time"].endswith(":60") and when is not None:
                        time_fields["time_note"] = "second 60 (a leap second) is shown as 59"
                    if reordered:
                        time_fields["reordered"] = True
                else:
                    info["formats"]["rfc3339"] = info["formats"].get("rfc3339", 0) + 1
                    shown, utc, zone, error, notes = iso_time(parts["stamp"])
                    time_fields = {"time": shown, "time_raw": parts["stamp"], "time_zone": zone, "time_utc": utc}
                    if error:
                        time_fields["time_error"] = error
                    if notes:
                        time_fields["time_note"] = "; ".join(notes)
                    range_key = utc.rstrip("Z") if utc else shown
                if range_key:
                    info["first_time"] = info["first_time"] or range_key
                    info["last_time"] = range_key
                if time_fields.get("time_error"):
                    counts["time_errors"] += 1
                kind, fields, typed = classify(parts["msg"])
                by_kind[kind] = by_kind.get(kind, 0) + 1
                if wanted and kind not in wanted:
                    continue
                texts = {"raw": parts["msg"]}
                if "command" in fields:
                    texts["command"] = fields.pop("command")
                withheld = {}
                for name in typed:
                    if name in fields:
                        texts[name] = fields.pop(name)
                        withheld[name + "_bytes"] = blen(texts[name])
                        withheld[name + "_withheld"] = True
                row_core = {**time_fields, "host": parts.get("host"), "process": parts.get("proc"), "kind": kind, **short_fields(fields), **withheld}
                if needle:
                    # Outside a job `contains` matches the fields the answer shows; in a job it matches the whole line.
                    if needle not in (line.lower() if in_job() else shown_text(row_core).lower()):
                        continue
                seq += 1
                info["records"] += 1
                record_id = "A%06d" % seq
                row = {"id": record_id, "parser": PARSER, "file": target, "line": number, "byte_offset": offset,
                       **row_core, "pid": int(parts["pid"]) if parts.get("pid") else None,
                       "text_bytes": blen(parts["msg"])}
                if "command" in texts:
                    row["command_bytes"] = blen(texts["command"])
                text.add({**row, **fields, **texts, "line_text": line})
                page.add(row)
                if preview_text and len(preview_rows) < limit:
                    preview_rows.append({**row, **texts})
        except Overtime:
            hit_deadline = True
            read_errors.append({"file": target, "error": "max_seconds (%s) passed while reading this file: it was not read further" % seconds, "line": None, "byte_offset": None})
            info["partial"] = True
        info["compression"] = state.compression
        if ranges:
            info["years_applied"] = [{"from_line": r[0], "year": r[1], "dated_lines": r[2]["lines"]} for r in ranges]
            info["years_span_rollover"] = spans_rollover
        for err in state.errors:
            read_errors.append(err)
            info["partial"] = True
        settle_file(info, mtime_ts, anchor_when)
    text.close()
    pages = {"records": page.finish(), "unparsed": unparsed_page.finish(), "forward_steps": steps_page.finish()}
    listed = {"files": files, "files_not_reached": not_reached, "cross_file_order_overlaps": overlaps, "read_errors": read_errors,
              "walk_errors": walk_errors, "skipped_symlinks": skipped_symlinks, "skipped_special": skipped_special}
    for key, items in listed.items():
        settled = items.settle()
        if settled["matched"]:
            pages[key] = settled      # a list with nothing in it has no page to name
    capped = capped_why(pages, text)
    n_read_errors, n_walk_errors, n_special, n_not_reached = (listed[k].page.total for k in ("read_errors", "walk_errors", "skipped_special", "files_not_reached"))
    all_parsed = counts["unparsed"] == 0 and not n_read_errors and not n_walk_errors and not n_special and not n_not_reached
    outcome = status_of(
        all_parsed and not capped, files.page.total == 0 or only_dead[0],
        "every line of every file matched a syslog shape and every file was read through",
        "%d line(s) matched no syslog shape, %d read error(s), %d walk error(s), %d special file(s) not opened, %d file(s) not reached%s: "
        "the answer names each" % (counts["unparsed"], n_read_errors, n_walk_errors, n_special, n_not_reached,
                                   "; " + capped if capped else ""),
        "no file could be read")
    hold_stop_signals()
    STATE["answering"] = True       # the answer is being written: a signal from here on does not start a second document
    print(json.dumps({
        "parser": PARSER,
        **outcome,
        "path": path,
        "files": files,
        "file_count": files.page.total,
        "files_not_reached": not_reached,
        "mixed_rotation_schemes": len(schemes) > 1,
        "cross_file_order": ("overlap" if overlaps else "not established: more than one rotation scheme" if len(schemes) > 1 else
                             "not established: a file is ordered by its name only" if files.page.total > 1 and any(r == 0 for (r, _k, _b), _t in ranked) else "consistent"),
        "cross_file_order_overlaps": overlaps,
        "physical_lines": counts["physical"],
        "blank_lines": counts["blank"],
        "lines_read": counts["read"],
        "unparsed_lines": counts["unparsed"],
        "lines_with_time_errors": counts["time_errors"],
        "lines_with_invalid_utf8": counts["invalid_utf8"],
        "by_kind": by_kind,
        "contains_scope": None if not needle else ("the whole line, in a job" if in_job() else "the fields the answer shows (outside a job the text is not matched)"),
        "filter_touched_withheld_text": touches_withheld_text(needle),
        "record_count": pages["records"]["matched"],
        "records": preview_rows if preview_text else page.page,
        "unparsed": unparsed_page.page,
        "pages": pages,
        "text": text.summary(preview_text),
        "all_lines_parsed": all_parsed,
        "read_errors": read_errors,
        "walk_errors": walk_errors,
        "skipped_symlinks": skipped_symlinks,
        "skipped_special": skipped_special,
        "truncated": any(p["truncated"] for p in pages.values()),
        "note": "A traditional syslog stamp carries no year and no zone: each file says the year basis applied "
                "(its modification time, which on a copied tree is the time of the copy, or your `year` or `years`) and each "
                "record keeps its stamp as written in time_raw, with `time` the clock reading as written and "
                "`time_utc` set only where the stamp carries its zone. A month that goes up is the log moving on "
                "however long the gap; a month that goes down is a year end only within six months after the last one, "
                "and a line the next line contradicts is flagged reordered and placed by nearness; rollover_lines "
                "names each year end that was read. The year is an inference: a gap of more than %d days between two "
                "lines is a forward step (forward_steps, whole in pages.forward_steps) across which any number of years "
                "may have passed, every record before the last one carries year_assumed, and a file's modification "
                "time may be the time of a copy (mtime_may_be_copy_time): fix the year from a source with full dates "
                "and pass `year` or `years` before a conclusion rests on a date. all_lines_parsed says that every line matched a syslog shape " % STEP_DAYS +
                "and every file was read through; it is not coverage of the host's authentication events. An "
                "ssh_accepted line says sshd accepted an authentication: its fingerprint names a key, not a person, "
                "and not when the key was installed. A PAM session is the named service's, not necessarily a login. A "
                "user name typed at a prompt (an invalid user, a PAM user=) can be a password: it is not in the answer, "
                "only its length (user_bytes), and is in the text file. Text files are editable by root: compare the "
                "sessions that matter with wtmp (utmp_parse) and the journal, and treat a disagreement as a question to "
                "explain (rotation, forwarding, filtering, a damaged file and an edit all produce one), not as an answer.",
    }, indent=2))


if __name__ == "__main__":
    exit_code = 0
    try:
        main()
    except SystemExit as stop:
        exit_code = _code(stop)
    _leave(exit_code)
