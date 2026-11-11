#!/usr/bin/env python3
"""Read wtmp, btmp, utmp and lastlog: Linux's binary login records, in the layouts this tool names.

wtmp holds sessions that started and ended with the source address, btmp the failed attempts (its user
field is what was typed, which may be no account), utmp the sessions now, lastlog the last login per UID.
They are written by login programs and PAM modules, and only by those that were configured to: a record
that is missing does not show that no login happened. They are not a log a root user cannot edit.

Three layouts are read, and the answer names the one it used and how it chose:

  utmp-384    glibc `struct utmp`, 384 bytes (wtmp, btmp, utmp):
                0x000 int16 ut_type    0x004 int32 ut_pid       0x008 char ut_line[32]   0x028 char ut_id[4]
                0x02c char ut_user[32] 0x04c char ut_host[256]  0x14c ut_exit (2 x int16) 0x150 int32 ut_session
                0x154 int32 tv_sec     0x158 int32 tv_usec      0x15c int32 ut_addr_v6[4] 0x16c unused[20]
              tv_sec is a signed 32-bit value. This is the layout of the glibc ABIs that store 32-bit times
              in it; a file in which the records are some other size is not read as this.
  lastlog-292 `struct lastlog` with a 32-bit ll_time, ll_line[32], ll_host[256], indexed by UID
  lastlog-296 the same with a 64-bit ll_time

The byte order of a utmp file is decided from the records: in the right order every non-empty record's
ut_type is 0 to 9, and in the wrong one it almost never is. Where that cannot decide (every record empty) the
answer says `undetermined`, and `byte_order` names it. A lastlog file's layout is decided by its size where
only one width divides it, by structure (every non-empty slot's two text fields are printable, NUL-padded
strings) where both do and the slots can tell, and is refused as ambiguous where nothing can tell: pass
`layout`. A lastlog byte order is the little-endian default unless `byte_order` says otherwise, and the answer
says it was not tested.

A microsecond field outside 0 to 999999 is not a time: the record keeps its raw seconds and microseconds, has
no `time` and says why. Nothing is reduced modulo anything to look plausible. An address whose first word is
the only non-zero one is shown as IPv4 and is also kept as raw hex, because an IPv6 address can look like one.

A file of SQLite (wtmpdb's wtmp table, lastlog2's lastlog2 table) is read from a copy of it, and of its -wal and -journal, kept in
the job's $OUT: the schema is read from sqlite_master and an unknown one is refused and listed, the copy is opened under an authorizer
that allows SELECT on that table only, the primary key is never selected, and a row is located by its ordinal. A lastlog file is read slot
by slot by UID, skipping holes of a sparse file, within `max_slots` and `max_seconds`; what is left unread is
named (`next_uid`), and `uids` reads only the slots named.
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
import hashlib
import json
import math
import os
import re
import secrets
import signal
import socket
import sqlite3
import stat
import struct
import sys
import tempfile
import time
import urllib.parse
from pathlib import Path

TOOL = "utmp_parse"
PARSER = "utmp_parse/16"


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
RECORD = 384
LASTLOG = {"lastlog-292": (292, 4, 4), "lastlog-296": (296, 8, 8)}   # slot width, bytes of ll_time, offset of ll_line
STRUCTURE_SLOTS = 20000        # non-empty slots examined per layout when structure has to decide
DEFAULT_SECONDS = 30.0
MAX_SECONDS = 45.0           # the most a caller may ask for (the manifest allows 60)
TEXT_NAME = "utmp-text.jsonl"
MAX_PASSWD = 8 << 20
SURVEY_RECORDS = 200000       # the byte order and the share of valid types are read from this many records
SHARE_FLOOR = 0.8             # fewer valid ut_type values than this and the file is not read as 384-byte records
CHUNK = 4 << 20
TYPES = {0: "EMPTY", 1: "RUN_LVL", 2: "BOOT_TIME", 3: "NEW_TIME", 4: "OLD_TIME",
         5: "INIT_PROCESS", 6: "LOGIN_PROCESS", 7: "USER_PROCESS", 8: "DEAD_PROCESS",
         9: "ACCOUNTING"}
EPOCH = datetime.datetime(1970, 1, 1)
SQLITE_MAGIC = b"SQLite format 3\x00"


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


REGEX_SECONDS = 2.0      # the most one match of the caller's expression may take; Python's re has no clock of its own


class RegexTooSlow(Exception):
    """A match of the caller's expression was ended. `by_deadline` is true when the cause was the tool's own max_seconds (the
    match had not been given its full REGEX_SECONDS because less time was left, or none was), false when one match used them all."""

    def __init__(self, by_deadline=False):
        super().__init__()
        self.by_deadline = by_deadline


CLOCK = {"by_deadline": False}      # whether the match now running was given the time left to the deadline and not the full REGEX_SECONDS


def _alarm(_signum, _frame):
    raise RegexTooSlow(CLOCK["by_deadline"])


def arm_regex_clock():
    """Make a match that runs too long end (SIGALRM, which Python's matcher polls): the expression is the caller's and the
    text is the evidence's (a btmp user field is whatever was typed), and a nested repeat on a few dozen characters runs for minutes."""
    if hasattr(signal, "setitimer"):
        signal.signal(signal.SIGALRM, _alarm)


def search_within(pattern, text, deadline):
    """pattern.search(text), ended at REGEX_SECONDS or at the tool's deadline, whichever is first (RegexTooSlow). It is called
    for every record, and what is left of the time is read each time: after the deadline no match is begun (there is no grace), and
    a match is given no more than the time that is left, so the tool always ends at its deadline and not at a coarser tick."""
    left = deadline - time.monotonic()
    if left <= 0.001:
        raise RegexTooSlow(True)
    if not hasattr(signal, "setitimer"):
        return pattern.search(text)
    CLOCK["by_deadline"] = left < REGEX_SECONDS
    signal.setitimer(signal.ITIMER_REAL, min(REGEX_SECONDS, left))
    try:
        return pattern.search(text)
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)


def slow_because(exc, what, after):
    """The sentence for a read ended by a match of the caller's expression: the deadline when it was the deadline (the match was
    not given its full REGEX_SECONDS, or none), the 2-second clock when one match used it all."""
    if exc.by_deadline:
        return "max_seconds passed while the user expression was being tested on %s: the read stopped there%s" % (what, after)
    return "the user expression did not finish within %s s on %s: the read stopped there%s" % (REGEX_SECONDS, what, after)


def text(raw):
    return decode(raw.split(b"\x00", 1)[0])


def address(raw):
    """ut_addr_v6 holds an IPv4 address in its first word, or a whole IPv6 one."""
    words = struct.unpack("<4I", raw)
    if not any(words):
        return None
    if not any(words[1:]):
        return socket.inet_ntop(socket.AF_INET, raw[:4])
    try:
        return socket.inet_ntop(socket.AF_INET6, raw)
    except (OSError, ValueError):
        return raw.hex()


def when(sec, usec=0):
    """(ISO 8601 UTC, error): a time only from a valid seconds and microseconds, the fraction kept."""
    if not sec and not usec:
        return None, None
    if usec < 0 or usec > 999999:
        return None, "tv_usec %d is outside 0..999999: the stored value is not a microsecond count" % usec
    try:
        return (EPOCH + datetime.timedelta(seconds=sec, microseconds=usec)).isoformat() + "Z", None
    except OverflowError:
        return None, "seconds %d are outside the range of a date" % sec


def open_evidence(path):
    """A binary file object on a regular file, opened without waiting and without following a link: a FIFO, a device or a directory at this
    name is an OSError, not a hang."""
    fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0))
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise OSError("not a regular file (a pipe, a socket or a device is never read)")
        return os.fdopen(fd, "rb")
    except BaseException:
        os.close(fd)
        raise


def passwd_users(path):
    """{uid: name} from a passwd file the caller names (a regular file, not a link or a pipe), and what was read."""
    users = {}
    if not path:
        return users, {"file": None, "uids_mapped": 0}
    try:
        if os.path.islink(path):
            fail("refusing a symlink passwd file", path=path, target=os.readlink(path))
        if not stat.S_ISREG(os.lstat(path).st_mode):
            fail("passwd must be a regular file: a pipe, a socket or a device is never opened", path=path)
        if os.path.getsize(path) > MAX_PASSWD:
            fail("passwd file larger than the %d bytes this tool reads" % MAX_PASSWD, path=path)
        with open_evidence(path) as fh:
            for raw in fh:
                fields = decode(raw).rstrip("\n").split(":")
                if len(fields) >= 3:
                    try:
                        users[int(fields[2])] = fields[0]
                    except ValueError:
                        continue
    except OSError as exc:
        fail("could not read passwd file", path=path, reason=describe(exc))
    return users, {"file": path, "uids_mapped": len(users)}


def printable_field(raw):
    """A strncpy'd text field: printable ASCII up to the first NUL, and NUL after it."""
    head, nul, tail = raw.partition(b"\x00")
    return all(0x20 <= b <= 0x7E for b in head) and not any(tail)


def slot_is_text(raw, width, line_at):
    return printable_field(raw[line_at:line_at + 32]) and printable_field(raw[line_at + 32:line_at + 288])


# --- utmp ------------------------------------------------------------------------------------------

def utmp_records(path, size, start=0):
    with open_evidence(path) as fh:
        index = start
        offset = start * RECORD
        fh.seek(offset)
        while offset + RECORD <= size:
            raw = fh.read(RECORD)
            if len(raw) < RECORD:
                return
            yield index, offset, raw
            index += 1
            offset += RECORD


def survey(path, size, budget):
    """How the records read in each byte order: of the non-empty records in a sample (the first SURVEY_RECORDS, or what
    fits the budget), how many have a ut_type of 1 to 9. Type 0 is not counted: a zero read from the wrong place is
    what a misaligned file is full of."""
    ok = {"little": 0, "big": 0}
    nonempty = sampled = 0
    deadline = time.monotonic() + budget
    for _i, _o, raw in utmp_records(path, size):
        sampled += 1
        if sampled % 4096 == 0 and time.monotonic() > deadline:
            break
        if any(raw):
            nonempty += 1
            for order, fmt in (("little", "<h"), ("big", ">h")):
                if 1 <= struct.unpack_from(fmt, raw, 0)[0] <= 9:
                    ok[order] += 1
        if sampled >= SURVEY_RECORDS:
            break
    return {"ok": ok, "nonempty": nonempty, "sampled": sampled}


def decide_byte_order(found):
    """(order, basis): which byte order makes the non-empty records' ut_type a value from 1 to 9."""
    ok, nonempty, sampled = found["ok"], found["nonempty"], found["sampled"]
    if nonempty == 0:
        return "undetermined", "structure cannot decide: every record in the %d sampled is empty" % sampled
    if ok["little"] > ok["big"]:
        return "little", "structure: ut_type is 1-9 in %d of %d non-empty records sampled read little-endian, %d read big-endian" % (ok["little"], nonempty, ok["big"])
    if ok["big"] > ok["little"]:
        return "big", "structure: ut_type is 1-9 in %d of %d non-empty records sampled read big-endian, %d read little-endian" % (ok["big"], nonempty, ok["little"])
    if ok["little"] == 0:
        return "neither", "structure: no non-empty record (of %d sampled) has a ut_type of 1-9 in either byte order" % nonempty
    return "ambiguous", "structure cannot decide: ut_type is 1-9 in %d of %d non-empty records sampled in either order" % (ok["little"], nonempty)


def parse_utmp(path, size, order, typed, args, pattern, wanted, page, text_file, preview, preview_rows, limit, stats, deadline, start):
    e = "<" if order != "big" else ">"
    for index, offset, raw in utmp_records(path, size, start):
        if ((index & 4095) == 4095 or pattern) and time.monotonic() > deadline:
            stats["stopped_at_record"] = index          # with an expression the clock is read for every record, not every 4,096th
            return
        stats["records"] += 1
        ut_type, pid = struct.unpack_from(e + "hxxi", raw, 0)
        exit_termination, exit_status = struct.unpack_from(e + "hh", raw, 0x14C)
        session = struct.unpack_from(e + "i", raw, 0x150)[0]
        sec, usec = struct.unpack_from(e + "ii", raw, 0x154)
        name = TYPES.get(ut_type)
        kind = name or "UNKNOWN"
        user, line, host = text(raw[0x02C:0x04C]), text(raw[0x008:0x028]), text(raw[0x04C:0x14C])
        stats["by_type"][kind] = stats["by_type"].get(kind, 0) + 1
        if kind == "BOOT_TIME":
            stats["boots"] += 1
        if kind == "EMPTY" and not user and not sec and not usec and not line and not host:
            stats["empty"] += 1
            continue
        if wanted and kind not in wanted:
            continue
        if pattern:
            # A typed name is text the answer withholds: it is matched only in a job.
            if typed and not in_job():
                continue
            try:
                if not search_within(pattern, user, deadline):
                    continue
            except RegexTooSlow as exc:
                stats["stopped_at_record"] = index
                stats["stopped_because"] = slow_because(exc, "record %d" % index, ", and no later record was tested")
                return
        shown, error = when(sec, usec)
        addr = raw[0x15C:0x16C]
        row = {"id": "U%06d" % (stats["matched"] + 1), "parser": PARSER, "record_index": index, "byte_offset": offset,
               "type": kind, "type_raw": ut_type, "line": line, "id_field": text(raw[0x028:0x02C]),
               "host": host, "address": address(addr), "address_raw": addr.hex(), "pid": pid, "session": session,
               "exit_termination": exit_termination, "exit_status": exit_status, "epoch": sec, "usec": usec, "time": shown}
        texts = {}
        if typed:
            row["user_bytes"], row["user_withheld"] = blen(user), True
            texts["user"] = user
        else:
            row["user"] = user
        if error:
            row["time_error"] = error
        stats["matched"] += 1
        text_file.add({**row, **texts})
        page.add(row)
        if preview and len(preview_rows) < limit:
            preview_rows.append({**row, **texts})


# --- lastlog ---------------------------------------------------------------------------------------

def data_regions(fd, size, begin, end, state):
    """(start, stop) byte ranges of [begin, end) that are not a hole. A file with no hole support is one range."""
    seek_data = getattr(os, "SEEK_DATA", None)
    seek_hole = getattr(os, "SEEK_HOLE", None)
    if seek_data is None or seek_hole is None:
        state["holes"] = False
        yield begin, end
        return
    pos = begin
    try:
        while pos < end:
            start = os.lseek(fd, pos, seek_data)
            if start >= end:
                return
            stop = os.lseek(fd, start, seek_hole)
            yield max(start, pos), min(stop, end)
            pos = stop
    except OSError as exc:
        import errno
        if exc.errno == errno.ENXIO:
            return        # no data after pos: the rest is a hole
        state["holes"] = False
        yield pos, end


def nonempty_slots(path, size, width, begin_uid, end_uid, state, deadline=None):
    """(uid, offset, raw) for each slot in [begin_uid, end_uid) that holds a non-zero byte, skipping holes.

    A chunk that is all zero is passed over whole. If `deadline` passes, the walk stops and
    state["stopped_at_uid"] is the first UID not examined."""
    fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0))
    last = begin_uid - 1
    try:
        lo, hi = begin_uid * width, end_uid * width
        for start, stop in data_regions(fd, size, lo, hi, state):
            pos = (start // width) * width
            while pos < stop:
                if deadline is not None and time.monotonic() > deadline:
                    state["stopped_at_uid"] = max(pos // width, begin_uid)
                    return
                length = min(CHUNK - CHUNK % width, stop - pos + width - 1, size - pos)
                data = os.pread(fd, length, pos)
                if len(data) < width:
                    return
                whole = (len(data) // width) * width
                if data.count(0) != len(data):
                    for k in range(0, whole, width):
                        slot = data[k:k + width]
                        if slot.count(0) != width:
                            uid = (pos + k) // width
                            if begin_uid <= uid < end_uid and uid > last:
                                last = uid
                                yield uid, pos + k, slot
                pos += whole
    finally:
        os.close(fd)


def lastlog_structure(path, size, width, text_at, budget_seconds):
    """(non-empty slots examined, those whose text fields are not text) under one width."""
    seen = bad = 0
    deadline = time.monotonic() + budget_seconds
    for _uid, _off, slot in nonempty_slots(path, size, width, 0, size // width, {"holes": True}, deadline):
        seen += 1
        if not slot_is_text(slot, width, text_at):
            bad += 1
        if seen >= STRUCTURE_SLOTS or time.monotonic() > deadline:
            break
    return seen, bad


def choose_lastlog_layout(path, size, requested):
    if requested in LASTLOG:
        return requested, "argument"
    fits = [name for name, (width, _t, _a) in LASTLOG.items() if size % width == 0]
    if not fits:
        fail("a lastlog file's size is not a whole number of 292-byte or 296-byte slots; pass layout to read whole slots anyway "
             "and have the short tail named", path=path, bytes=size, candidates=sorted(LASTLOG))
    if len(fits) == 1:
        return fits[0], "size: %d bytes is a whole number of %d-byte slots and not of the other width" % (size, LASTLOG[fits[0]][0])
    results = {}
    for name in fits:
        width, _t, text_at = LASTLOG[name]
        results[name] = lastlog_structure(path, size, width, text_at, 3.0)
    clean = [n for n, (seen, bad) in results.items() if seen > 0 and bad == 0]
    broken = [n for n, (seen, bad) in results.items() if bad > 0]
    if len(clean) == 1 and len(broken) == len(fits) - 1:
        n = clean[0]
        return n, "structure: all %d non-empty slots read as %s have printable, NUL-padded line and host fields; %s" % (
            results[n][0], n, "; ".join("%s: %d of %d slots do not" % (b, results[b][1], results[b][0]) for b in broken))
    fail("the lastlog layout is ambiguous: the size divides by both 292 and 296 and the slots cannot tell them apart "
         "(%s). Pass layout: lastlog-292 or lastlog-296" % "; ".join("%s: %d non-empty slots, %d not text" % (n, s, b) for n, (s, b) in results.items()),
         ambiguous=True, candidates=sorted(fits), path=path, bytes=size)


def parse_lastlog(path, size, layout, order, args, pattern, wanted, page, stats, deadline):
    width, time_bytes, text_at = LASTLOG[layout]
    e = "<" if order != "big" else ">"
    fmt = e + ("i" if time_bytes == 4 else "q")
    users, passwd_info = passwd_users(args.get("passwd"))
    stats["passwd"] = passwd_info
    total = size // width
    selected = args.get("uids")
    state = {"holes": True}
    if selected is not None:
        if not isinstance(selected, list) or not all(isinstance(u, int) and not isinstance(u, bool) and u >= 0 for u in selected):
            fail("uids must be a list of whole numbers (UIDs)")
        stats["scope"] = "selected UIDs"
        fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0))
        try:
            for uid in sorted(set(selected)):
                if uid >= total:
                    stats["uids_beyond_file_count"] = stats.get("uids_beyond_file_count", 0) + 1
                    if len(stats["uids_beyond_file"]) < INLINE_LIST:       # the caller gave them: the first INLINE_LIST are echoed, the rest counted
                        stats["uids_beyond_file"].append(uid)
                    continue
                slot = os.pread(fd, width, uid * width)
                stats["slots_read"] += 1
                if slot.count(0) != len(slot):
                    stats["nonempty"] += 1
                try:
                    emit_slot(uid, uid * width, slot, width, fmt, time_bytes, text_at, users, pattern, wanted, page, stats, layout, deadline)
                except RegexTooSlow as exc:
                    stats["slots_read"] -= 1
                    stats["nonempty"] -= 1 if slot.count(0) != len(slot) else 0     # a slot that was not emitted is not counted
                    stats["stopped"] = "max_seconds" if exc.by_deadline else "expression"
                    stats["next_uid"] = uid
                    stats["stopped_because"] = slow_because(exc, "slot %d" % uid, "")
                    return
        finally:
            os.close(fd)
        stats["next_uid"] = None
        return
    start = args.get("start_uid", 0)
    cap = args.get("max_slots")
    if isinstance(start, bool) or not isinstance(start, int) or start < 0:
        fail("start_uid must be a whole number")
    if cap is not None and (isinstance(cap, bool) or not isinstance(cap, int) or cap < 1):
        fail("max_slots must be a positive whole number")
    if start > total:
        fail("start_uid is past the last slot of the file (%d slots)" % total, slots_total=total)
    end = total if cap is None else min(total, start + cap)
    stats["scope"] = "whole file" if start == 0 and end == total else "uid %d to %d" % (start, end - 1)
    for uid, offset, slot in nonempty_slots(path, size, width, start, end, state, deadline):
        stats["nonempty"] += 1
        try:
            emit_slot(uid, offset, slot, width, fmt, time_bytes, text_at, users, pattern, wanted, page, stats, layout, deadline)
        except RegexTooSlow as exc:
            stats["nonempty"] -= 1
            state["stopped_at_uid"] = uid
            state["by_deadline"] = exc.by_deadline
            stats["stopped_because"] = slow_because(exc, "slot %d" % uid, ", and no later slot was tested")
            break
    if "stopped_at_uid" in state:
        stats["slots_read"] = state["stopped_at_uid"] - start
        stats["next_uid"] = state["stopped_at_uid"]
        stats["stopped"] = "expression" if stats.get("stopped_because") and not state.get("by_deadline") else "max_seconds"
    else:
        stats["slots_read"] = end - start
        stats["next_uid"] = end if end < total else None
    stats["holes_skipped"] = state["holes"]


def emit_slot(uid, offset, slot, width, fmt, time_bytes, text_at, users, pattern, wanted, page, stats, layout, deadline):
    if slot.count(0) == width:
        return
    sec = struct.unpack_from(fmt, slot, 0)[0]
    line, host = text(slot[text_at:text_at + 32]), text(slot[text_at + 32:text_at + 288])
    user = users.get(uid)
    if wanted and "LASTLOG" not in wanted:
        return
    if pattern and not search_within(pattern, user or str(uid), deadline):
        return
    shown, error = when(sec, 0)
    row = {"id": "U%06d" % (stats["matched"] + 1), "parser": PARSER, "type": "LASTLOG", "uid": uid, "slot": uid,
           "byte_offset": offset, "layout": layout, "user": user, "line": line, "host": host, "epoch": sec, "time": shown}
    if error:
        row["time_error"] = error
    if not slot_is_text(slot, width, text_at):
        row["text_fields_valid"] = False
    stats["matched"] += 1
    page.add(row)


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


# --- wtmpdb and lastlog2 (SQLite) --------------------------------------------------------------------

SQLITE_FORMATS = ("wtmpdb", "lastlog2", "sqlite")
SNAPSHOT_MAX = 1 << 30            # the most of a database, and of its write-ahead log or journal, this tool copies
SQL_TEXT = 256                    # bytes of a text column kept in a record (its length is kept beside it)
SQL_LISTED = 50                   # tables, and columns of a table, named when a schema is refused
SQL_SCHEMA_ROWS = 2000            # rows of sqlite_master read
SQL_FUNCTIONS = {"typeof", "substr", "length", "count"}
SESSION_COLUMNS = {"wtmpdb": {"table": "wtmp", "required": ("user", "login"), "optional": ("type", "logout", "tty", "remotehost", "service")},
                   "lastlog2": {"table": "lastlog2", "required": ("name", "login"), "optional": ("tty", "remotehost", "service")}}


class SessionDbRefused(Exception):
    pass


def sql_ident(name):
    return '"' + name.replace('"', '""') + '"'


def shown_name(value, limit=100):
    """A name out of a database as text an answer can carry: control characters as escapes, cut at `limit` characters."""
    text_ = value if isinstance(value, str) else str(value)
    text_ = "".join(c if c.isprintable() else "\\x%02x" % ord(c) if ord(c) < 256 else "\\u%04x" % ord(c) for c in text_[:limit * 2])
    return text_[:limit]


def session_time(value):
    """(unit, ISO 8601 UTC, error) for a stored time. The unit is told from the size of the number (microseconds from 1e14, milliseconds from
    1e11, seconds below) because the schema does not say it; the raw number is always kept beside the result."""
    if value is None:
        return None, None, None
    try:
        magnitude = abs(value)
        if magnitude != magnitude or magnitude == float("inf"):
            return None, None, "the stored number is not finite"
        if magnitude >= 10 ** 14:
            unit = "microseconds"
            sec, usec = divmod(int(value), 10 ** 6)
        elif magnitude >= 10 ** 11:
            unit = "milliseconds"
            sec, milli = divmod(int(value), 1000)
            usec = milli * 1000
        else:
            unit, sec, usec = "seconds", int(value), 0
    except (OverflowError, ValueError):
        return None, None, "the stored number is outside any range this tool converts"
    shown, error = when(sec, usec)
    return unit, shown, error


def copy_member(source, dest_dir, name, deadline):
    """Copy one regular file (never a link or a pipe) into the snapshot directory: mode 0600, a name that is not there yet, hashed as it is copied."""
    flags = os.O_RDONLY | os.O_NONBLOCK | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    fd = os.open(source, flags)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise SessionDbRefused("not a regular file")
        if st.st_size > SNAPSHOT_MAX:
            raise SessionDbRefused("larger than the %d bytes this tool copies" % SNAPSHOT_MAX)
        target = os.path.join(dest_dir, name)
        ofd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0), 0o600)
        digest, total = hashlib.sha256(), 0
        try:
            while True:
                if time.monotonic() > deadline:
                    raise SessionDbRefused("max_seconds passed while the file was being copied")
                chunk = os.read(fd, 1 << 20)
                if not chunk:
                    break
                total += len(chunk)
                if total > SNAPSHOT_MAX:
                    raise SessionDbRefused("grew past the %d bytes this tool copies while it was read" % SNAPSHOT_MAX)
                digest.update(chunk)
                view = memoryview(chunk)
                while view:
                    view = view[os.write(ofd, view):]
        finally:
            os.close(ofd)
        return {"bytes": total, "sha256": digest.hexdigest(), "copy": target}
    finally:
        os.close(fd)


def wal_facts(path):
    """What the header of the copied write-ahead log says: the page size and the frames its size holds, or that it is not one."""
    try:
        with open(path, "rb") as fh:
            head = fh.read(32)
        size = os.path.getsize(path)
    except OSError as exc:
        return {"state": "could not be read: %s" % describe(exc)}
    if len(head) < 32 or struct.unpack(">I", head[:4])[0] not in (0x377F0682, 0x377F0683):
        return {"state": "the header is not a write-ahead log's: SQLite will not apply it", "bytes": size}
    page = struct.unpack(">I", head[8:12])[0]
    frames = (size - 32) // (page + 24) if page else 0
    return {"state": "a write-ahead log header; SQLite applies the committed frames to the copy", "page_size": page, "frames_by_size": frames, "bytes": size}


def snapshot_session_db(path, out_dir, deadline):
    """Copy the database, and its -wal and -journal when they are regular files, into a new directory of $OUT. The evidence is only read;
    SQLite works on the copy (it may checkpoint into it), never beside the evidence."""
    snap = tempfile.mkdtemp(prefix="session-db-", dir=out_dir)
    os.chmod(snap, 0o700)
    files = {}
    problems = []
    try:
        files["database"] = copy_member(path, snap, "db", deadline)
    except (OSError, SessionDbRefused) as exc:
        raise SessionDbRefused("the database could not be copied: %s" % (describe(exc) if isinstance(exc, OSError) else exc))
    for suffix, label in (("-wal", "wal"), ("-journal", "journal")):
        side = path + suffix
        try:
            mode = os.lstat(side).st_mode
        except FileNotFoundError:
            files[label] = {"state": "not there"}
            continue
        except OSError as exc:
            files[label] = {"state": "could not be examined: %s" % describe(exc)}
            problems.append("the %s could not be examined" % label)
            continue
        if stat.S_ISLNK(mode) or not stat.S_ISREG(mode):
            files[label] = {"state": "not copied: a link or a file that is not a regular file is never followed or opened"}
            problems.append("the %s is a link or not a regular file: its rows were not applied" % label)
            continue
        try:
            files[label] = copy_member(side, snap, "db" + suffix, deadline)
        except (OSError, SessionDbRefused) as exc:
            files[label] = {"state": "not copied: %s" % (describe(exc) if isinstance(exc, OSError) else exc)}
            problems.append("the %s was not copied: its rows were not applied" % label)
    if "copy" in files.get("wal", {}):
        files["wal"].update(wal_facts(files["wal"]["copy"]))
    files["shm"] = {"state": "never copied: SQLite rebuilds the index of a write-ahead log from the log itself"}
    return snap, files, problems


def open_session_db(db_copy, deadline, allowed):
    con = sqlite3.connect("file:%s?mode=rw" % urllib.parse.quote(db_copy), uri=True, timeout=0, check_same_thread=False)
    con.text_factory = lambda raw: raw.decode("utf-8", "surrogateescape")
    if hasattr(con, "setlimit") and hasattr(sqlite3, "SQLITE_LIMIT_LENGTH"):
        con.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, 1 << 24)
    con.execute("PRAGMA query_only=ON").fetchall()

    def authorizer(action, arg1, arg2, _dbname, _source):
        if action == sqlite3.SQLITE_SELECT:
            return sqlite3.SQLITE_OK
        if action == sqlite3.SQLITE_READ:
            return sqlite3.SQLITE_OK if (arg1 or "").lower() in allowed else sqlite3.SQLITE_DENY
        if action == sqlite3.SQLITE_FUNCTION:
            return sqlite3.SQLITE_OK if (arg2 or "").lower() in SQL_FUNCTIONS else sqlite3.SQLITE_DENY
        if action == sqlite3.SQLITE_PRAGMA:
            return sqlite3.SQLITE_OK if (arg1 or "").lower() == "table_info" else sqlite3.SQLITE_DENY
        return sqlite3.SQLITE_DENY

    con.set_authorizer(authorizer)
    con.set_progress_handler(lambda: 1 if time.monotonic() > deadline else 0, 2000)
    return con


def read_schema(con):
    """{lower-cased table name: {name, virtual, columns}} for the tables of the file, and the other objects it holds."""
    rows = con.execute("SELECT type, name, sql FROM sqlite_master").fetchmany(SQL_SCHEMA_ROWS + 1)
    schema = {"tables": {}, "others": [], "truncated": len(rows) > SQL_SCHEMA_ROWS}
    for kind, name, sql in rows[:SQL_SCHEMA_ROWS]:
        if kind == "table" and not name.lower().startswith("sqlite_"):
            virtual = (sql or "").lstrip()[:20].upper().startswith("CREATE VIRTUAL")
            entry = {"name": name, "virtual": virtual, "columns": []}
            if not virtual:
                entry["columns"] = [r[1] for r in con.execute("PRAGMA table_info(%s)" % sql_ident(name)).fetchmany(1000)]
            schema["tables"][name.lower()] = entry
        elif kind in ("view", "trigger", "table", "index"):
            schema["others"].append((kind, name))
    return schema


def schema_listing(schema):
    tables = list(schema["tables"].values())
    return {"tables": [{"name": shown_name(t["name"]), "virtual": t["virtual"], "columns": [shown_name(c) for c in t["columns"][:SQL_LISTED]],
                        "columns_total": len(t["columns"])} for t in tables[:SQL_LISTED]],
            "tables_total": len(tables), "other_objects": [[k, shown_name(n)] for k, n in schema["others"][:SQL_LISTED]], "other_objects_total": len(schema["others"]),
            "sqlite_master_truncated": schema["truncated"]}


def choose_session_format(schema, requested):
    """(format, table entry, columns by lower-cased name): from the tables the file holds, never from a list of releases; a schema it does not know is refused and listed."""
    found = []
    for fmt, spec in SESSION_COLUMNS.items():
        entry = schema["tables"].get(spec["table"])
        if entry is None:
            continue
        if entry["virtual"]:
            raise SessionDbRefused("the table %s is a virtual table: its rows come from a module and are not read" % spec["table"])
        lowered = {c.lower(): c for c in entry["columns"]}
        if all(c in lowered for c in spec["required"]):
            found.append((fmt, entry, lowered))
    if any(n.lower() == spec["table"] and k == "view" for spec in SESSION_COLUMNS.values() for k, n in schema["others"]):
        raise SessionDbRefused("a view is named like a session table: a view is not a table and is not read")
    if requested in ("wtmpdb", "lastlog2"):
        found = [f for f in found if f[0] == requested]
    if not found:
        raise SessionDbRefused("this SQLite file has no table this tool knows as %s (a table wtmp with the columns User and Login, or lastlog2 with Name and Login): its schema is listed" %
                               (requested if requested in ("wtmpdb", "lastlog2") else "wtmpdb or lastlog2"))
    if len(found) > 1:
        raise SessionDbRefused("this file holds both a wtmp and a lastlog2 table: name the one to read with format: wtmpdb or lastlog2")
    return found[0]


def parse_session_db(fmt, entry, lowered, con, pattern, wanted, page, stats, deadline, database_name):
    spec = SESSION_COLUMNS[fmt]
    picked = [(c, lowered[c]) for c in spec["required"] + spec["optional"] if c in lowered]
    taken = {c for c, _name in picked}
    unread = [shown_name(name) for lc, name in lowered.items() if lc not in taken]
    table = entry["name"]
    select = []
    for _key, column in picked:
        q = sql_ident(column)
        select.append("typeof(%s), CASE WHEN typeof(%s)='integer' THEN %s END, CASE WHEN typeof(%s)='real' THEN %s END, substr(CAST(%s AS BLOB),1,%d), length(CAST(%s AS BLOB))" %
                      (q, q, q, q, q, q, SQL_TEXT, q))
    try:
        stats["table_rows"] = con.execute("SELECT count(*) FROM %s" % sql_ident(table)).fetchone()[0]
    except sqlite3.Error as exc:
        stats["table_rows"] = None
        stats["count_error"] = describe(exc)
    sql = "SELECT %s FROM %s ORDER BY rowid" % (", ".join(select), sql_ident(table))
    try:
        cur = con.execute(sql)
        ordered = True
    except sqlite3.OperationalError:
        cur = con.execute(sql.replace(" ORDER BY rowid", ""))
        ordered = False
    keys = [k for k, _c in picked]
    units = {}
    ordinal = 0
    result = (picked, unread, units, ordered)
    try:
        for values in cur:
            if (ordinal & 255) == 255 and time.monotonic() > deadline:
                stats["stopped_at_record"] = ordinal
                stats["stopped_because"] = "max_seconds passed: the rows after ordinal %d were not read" % ordinal
                break
            cells = {}
            for i, key in enumerate(keys):
                kind, integer, real, head, length = values[5 * i:5 * i + 5]
                cells[key] = (kind, integer if integer is not None else real, head, length)
            ordinal += 1
            stats["records"] += 1
            user, user_extra = session_text(cells, "user" if fmt == "wtmpdb" else "name")
            kind_name = "LASTLOG"
            type_raw = None
            if fmt == "wtmpdb":
                tkind, tnum, _h, _l = cells.get("type", ("null", None, None, None))
                type_raw = int(tnum) if tkind == "integer" else None
                kind_name = (TYPES.get(type_raw) or "UNKNOWN") if type_raw is not None else "UNKNOWN"
            stats["by_type"][kind_name] = stats["by_type"].get(kind_name, 0) + 1
            if kind_name == "BOOT_TIME":
                stats["boots"] += 1
            if wanted and kind_name not in wanted:
                continue
            if pattern:
                try:
                    if not search_within(pattern, user or "", deadline):
                        continue
                except RegexTooSlow as exc:
                    stats["stopped_at_record"] = ordinal - 1
                    stats["stopped_because"] = slow_because(exc, "row %d" % (ordinal - 1), ", and no later row was tested")
                    return result
            row = {"id": "U%06d" % (stats["matched"] + 1), "parser": PARSER, "source": fmt, "database": shown_name(database_name, 200), "table": spec["table"],
                   "ordinal": ordinal - 1, "type": kind_name}
            if type_raw is not None:
                row["type_raw"] = type_raw
            row["user"] = user
            row.update(user_extra)
            for key, label in (("tty", "line"), ("remotehost", "host"), ("service", "service")):
                if key in cells:
                    value, extra = session_text(cells, key)
                    row[label] = value
                    row.update({k.replace(key, label, 1): v for k, v in extra.items()})
            for key in ("login", "logout"):
                if key not in cells:
                    continue
                kind, number, _head, _length = cells[key]
                row[key + "_raw"] = number
                if kind in ("integer", "real"):
                    unit, shown, error = session_time(number)
                    row[key + "_unit"], row[key + "_time"] = unit, shown
                    if unit:
                        units[unit] = units.get(unit, 0) + 1
                    if error:
                        row[key + "_error"] = error
                elif kind != "null":
                    row[key + "_error"] = "the stored value is %s, not a number" % kind
            stats["matched"] += 1
            page.add(row)
    except (ValueError, OverflowError, TypeError, UnicodeError, RecursionError) as exc:
        # a row the tool could not turn into a record ends the read with the rows before it, and says so
        stats["read_error"] = "row %d could not be read as a record: %s" % (ordinal, describe(exc))
    except sqlite3.Error as exc:
        stats["read_error"] = describe(exc)
        if "interrupt" in str(exc).lower():
            stats["stopped_at_record"] = ordinal
            stats["stopped_because"] = "max_seconds passed inside a read of the database: the rows after ordinal %d were not read" % ordinal
            stats.pop("read_error")
    return result


def session_text(cells, key):
    """(text, extra fields) of a text column: the first SQL_TEXT bytes, the length beside it when it was cut, and the type when it was not text."""
    if key not in cells:
        return None, {}
    kind, number, head, length = cells[key]
    if kind == "null":
        return None, {}
    if kind in ("integer", "real"):
        return str(number), {key + "_stored_as": kind}
    raw = head if isinstance(head, bytes) else (b"" if head is None else str(head).encode("utf-8", "surrogateescape"))
    extra = {}
    if kind == "blob":
        extra[key + "_stored_as"] = "blob"
    if length is not None and length > SQL_TEXT:
        extra[key + "_bytes"], extra[key + "_truncated"] = length, True
    return decode(raw), extra


def main_session_db(args, path, size, requested_format):
    """A SQLite file: wtmpdb or lastlog2, read from a copy of it that lives in $OUT."""
    if not in_job():
        fail("a SQLite file is read from a copy of it, and the copy is kept in the job's $OUT: run this as job_run tool=utmp_parse. Nothing was read.",
             path=path, format="sqlite", bytes=size)
    bad = [k for k in ("uids", "start_uid", "max_slots", "passwd", "start_record", "user_is_typed", "layout", "byte_order", "write_text", "preview_text") if k in args]
    if bad:
        fail("%s apply to a utmp, wtmp, btmp or lastlog file only: this file is a SQLite database" % ", ".join(bad), path=path)
    limit = want_limit(args)
    wanted = {t.upper() for t in want_str_list(args, "types")}
    pattern = None
    if want_str(args, "user"):
        try:
            pattern = re.compile(args["user"], re.I)
        except (re.error, RecursionError, OverflowError, ValueError) as exc:
            fail("user is not a valid regex", reason=str(exc))
        arm_regex_clock()
    seconds = want_seconds(args, "max_seconds", DEFAULT_SECONDS, MAX_SECONDS)
    deadline = time.monotonic() + seconds
    page = LosslessPage(TOOL, "records", limit)
    stats = {"records": 0, "matched": 0, "boots": 0, "by_type": {}}
    out = {"parser": PARSER, "path": path, "bytes": size}
    snap = con = None
    files = {}
    problems = []
    try:
        snap, files, snap_problems = snapshot_session_db(path, os.environ["OUT"], deadline)
        problems.extend(snap_problems)
        allowed = {"sqlite_master", "sqlite_schema"}
        con = open_session_db(files["database"]["copy"], deadline, allowed)
        schema = read_schema(con)
        try:
            fmt, entry, lowered = choose_session_format(schema, requested_format)
        except SessionDbRefused as exc:
            fail(str(exc), path=path, format="sqlite", schema=schema_listing(schema), snapshot=snap)
        allowed.add(entry["name"].lower())
        picked, unread, units, ordered = parse_session_db(fmt, entry, lowered, con, pattern, wanted, page, stats, deadline, os.path.basename(path))
    except SessionDbRefused as exc:
        fail(str(exc), path=path, format="sqlite", bytes=size)
    except sqlite3.Error as exc:
        fail("the file could not be read as a database: %s" % describe(exc), path=path, format="sqlite", bytes=size, snapshot=snap)
    except OSError as exc:
        fail("the file could not be copied or read: %s" % describe(exc), path=path)
    finally:
        if con is not None:
            try:
                con.close()
            except sqlite3.Error:
                pass
    pages = {"records": page.finish()}
    stopped = stats.get("stopped_at_record")
    read_error = stats.get("read_error")
    whole = (stopped is None and read_error is None and not problems and stats.get("table_rows") is not None and stats["records"] == stats["table_rows"])
    complete = whole
    if stopped is not None:
        problems.append(stats.get("stopped_because") or "the read stopped")
    if read_error:
        problems.append("the database failed after %d row(s): %s" % (stats["records"], read_error))
    if stats.get("count_error"):
        problems.append("the rows of the table could not be counted (%s), so a complete read cannot be shown" % stats["count_error"])
    capped = capped_why(pages, None)
    if capped:
        complete = False
        problems.append(capped)
    out.update({
        "format": fmt,
        "format_basis": "told from the tables the file holds (sqlite_master), not from a release: " +
                        ("named by the caller and found" if requested_format in ("wtmpdb", "lastlog2") else "the only one of the two known tables that is there, with its required columns"),
        "snapshot": {"directory": snap, "files": {k: {kk: vv for kk, vv in v.items() if kk != "copy"} for k, v in files.items()},
                     "note": "the evidence was only read; SQLite opened the copy (it may have checkpointed the log into it), and the hashes are of the bytes as copied"},
        "schema": {"table": shown_name(entry["name"]), "columns": [shown_name(c) for c in entry["columns"][:SQL_LISTED]], "columns_total": len(entry["columns"]),
                   "columns_read": [shown_name(name) for _c, name in picked], "columns_not_read": unread[:SQL_LISTED],
                   "keys": ("the ID column is never selected" if fmt == "wtmpdb" else "Name, the key of the table, is the account and is shown as user") + ("; a row is located by its ordinal in rowid order" if ordered else "; the table has no rowid, so the ordinal is the order SQLite gave")},
        "records_in_table": stats.get("table_rows"), "records_read": stats["records"], "by_type": stats["by_type"], "boots": stats["boots"],
        "time_units": units, "stopped_at_record": stopped, "stopped_because": stats.get("stopped_because"), "read_error": read_error,
        "all_records_read": whole,
        "note": ("Each row of wtmpdb is a session record its writer stored; Login and Logout are kept raw beside the time, whose unit is told from the size of the number "
                 "(the schema does not say it). A missing row is not a login that did not happen. Type is read with utmp.h's numbering, which is an assumption: type_raw is kept. "
                 if fmt == "wtmpdb" else
                 "Each row of lastlog2 is the most recent login stored for one name. A name with no row is not shown never to have logged in. Login is kept raw beside the time, whose unit is told from the size of the number. ")
                + "A write-ahead log was applied to the copy only where the snapshot says it was copied and has a log header.",
    })
    out.update({**status_of(complete, False, "every row of the table was read from the copy, with its write-ahead log applied when there was one",
                            "; ".join(problems) or "a filter or a type list left rows out", ""),
                "text": {"written": False, "note": "no text file: a SQLite session record has no typed name to withhold"},
                "record_count": pages["records"]["matched"], "records": page.page, "pages": pages, "truncated": pages["records"]["truncated"]})
    hold_stop_signals()
    STATE["answering"] = True
    print(json.dumps(out, indent=2))
    sys.exit(0)


def main():
    args = read_args()
    path = want_str(args, "path", "path is required: a wtmp, btmp, utmp or lastlog file")
    try:
        if os.path.islink(path):
            fail("refusing a symlink: pass the binary log inside the evidence", path=path, target=os.readlink(path))
        if not os.path.exists(path):
            fail("no such file", path=path)
        if not stat.S_ISREG(os.lstat(path).st_mode):
            fail("not a regular file: a pipe, a socket or a device is never opened", path=path)
        refuse_disk_image(path, "path")
        size = os.path.getsize(path)
        with open_evidence(path) as fh:
            head = fh.read(16)
    except OSError as exc:
        fail("the file cannot be read", path=path, reason=describe(exc))
    requested_format = args.get("format")
    if requested_format not in (None, "utmp", "lastlog") + SQLITE_FORMATS:
        fail("format must be utmp, lastlog, wtmpdb, lastlog2 or sqlite")
    if head.startswith(SQLITE_MAGIC):
        if requested_format in ("utmp", "lastlog"):
            fail("format %s was asked for, but this file is a SQLite database: name wtmpdb, lastlog2 or sqlite" % requested_format, path=path, format="sqlite", bytes=size)
        main_session_db(args, path, size, requested_format)
    if requested_format in SQLITE_FORMATS:
        fail("format %s was asked for, but this file does not start as a SQLite database" % requested_format, path=path, bytes=size)
    limit = want_limit(args)
    write_text, preview_text = want_flag(args, "write_text"), want_flag(args, "preview_text")
    if preview_text:
        require_job("preview_text")
    wanted = {t.upper() for t in want_str_list(args, "types")}
    pattern = None
    if want_str(args, "user"):
        try:
            pattern = re.compile(args["user"], re.I)
        except (re.error, RecursionError, OverflowError, ValueError) as exc:
            fail("user is not a valid regex", reason=str(exc))
        arm_regex_clock()
    want_str(args, "passwd")
    layout_arg = args.get("layout", "auto")
    if layout_arg not in ("auto", "utmp-384", "lastlog-292", "lastlog-296"):
        fail("layout must be auto, utmp-384, lastlog-292 or lastlog-296")
    order_arg = args.get("byte_order", "auto")
    if order_arg not in ("auto", "little", "big"):
        fail("byte_order must be auto, little or big")
    typed_arg = args.get("user_is_typed", "auto")
    if typed_arg not in ("auto", "true", "false"):
        fail("user_is_typed must be auto, true or false")
    seconds = want_seconds(args, "max_seconds", DEFAULT_SECONDS, MAX_SECONDS)
    base = os.path.basename(path).lower()
    is_lastlog = (requested_format == "lastlog" or layout_arg.startswith("lastlog")
                  or (requested_format is None and layout_arg == "auto" and base.startswith("lastlog")))
    if requested_format == "utmp" and layout_arg.startswith("lastlog") or requested_format == "lastlog" and layout_arg == "utmp-384":
        fail("format and layout disagree", format=requested_format, layout=layout_arg)
    lastlog_only = [k for k in ("uids", "start_uid", "max_slots", "passwd") if k in args]
    utmp_only = [k for k in ("start_record", "user_is_typed") if k in args]
    if not is_lastlog and lastlog_only:
        fail("%s apply to a lastlog file only (its slots are indexed by UID): this file is read as utmp" % ", ".join(lastlog_only), path=path)
    if is_lastlog and utmp_only:
        fail("%s apply to a utmp, wtmp or btmp file only: this file is read as lastlog" % ", ".join(utmp_only), path=path)
    start_record = args.get("start_record", 0)
    if isinstance(start_record, bool) or not isinstance(start_record, int) or start_record < 0:
        fail("start_record must be a whole number")
    if start_record > 1 << 50:
        fail("start_record is larger than any file can hold records (at most %d)" % (1 << 50))
    typed = (typed_arg == "true") or (typed_arg == "auto" and base.startswith("btmp"))
    if pattern is not None and typed and not is_lastlog and not in_job():
        fail("user is refused outside a job on a file whose user field is typed text (btmp): the field is withheld from this answer, so "
             "a filter on it would match nothing and read as 'no such user'. Run this as job_run tool=utmp_parse with secret_output: true "
             "and ask again there, or drop user and read the records (their user_bytes) instead. Nothing was read.", path=path, user_is_typed=True)
    try:
        text_file = TextFile(TEXT_NAME, write_text, "JSON Lines, mode 0600: the record's id and locator as in the answer, with `user` where it is a name someone typed (btmp)")
    except TextRefused as exc:
        fail(str(exc))
    page = LosslessPage(TOOL, "records", limit)
    STATE["text"] = text_file
    preview_rows = []
    stats = {"records": 0, "empty": 0, "matched": 0, "boots": 0, "by_type": {}, "slots_read": 0, "nonempty": 0,
             "scope": "whole file", "next_uid": None, "uids_beyond_file": [], "passwd": {"file": None, "uids_mapped": 0}}
    deadline = time.monotonic() + seconds
    out = {"parser": PARSER, "path": path, "bytes": size}
    complete = False
    basis_complete = basis_partial = ""
    if is_lastlog and size == 0:
        out["layout"] = {"name": None, "basis": "the file is empty: it holds no slot, so no layout is needed"}
        out.update({"slots_total": 0, "slots_read": 0, "nonempty_slots": 0, "scope": "whole file", "next_uid": None,
                    "trailing_bytes": 0, "all_records_read": True,
                    "note": "An empty lastlog file holds no slot."})
        complete, basis_complete = True, "the file is empty: there was nothing to read"
    elif is_lastlog:
        try:
            layout, basis = choose_lastlog_layout(path, size, layout_arg)
            width = LASTLOG[layout][0]
            order = "big" if order_arg == "big" else "little"
            order_basis = "argument" if order_arg != "auto" else "default assumption, not tested: a lastlog slot has no field to test it by"
            out["layout"] = {"name": layout, "slot_bytes": width, "basis": basis, "byte_order": order, "byte_order_basis": order_basis}
            parse_lastlog(path, size, layout, order, args, pattern, wanted, page, stats, deadline)
        except OSError as exc:
            fail("the file could not be read: %s" % describe(exc), path=path)
        whole = stats["scope"] == "whole file" and stats["next_uid"] is None and stats.get("stopped") is None and size % width == 0
        out.update({
            "slots_total": size // width,
            "slots_read": stats["slots_read"],
            "nonempty_slots": stats["nonempty"],
            "scope": stats["scope"],
            "next_uid": stats["next_uid"],
            "stopped": stats.get("stopped"),
            "stopped_because": stats.get("stopped_because"),
            "holes_skipped": stats.get("holes_skipped"),
            "uids_beyond_file": stats["uids_beyond_file"],
            "uids_beyond_file_count": stats.get("uids_beyond_file_count", 0),
            "trailing_bytes": size % width,
            "trailing_offset": (size // width) * width if size % width else None,
            "all_records_read": whole,
            "note": "Each LASTLOG record is the most recent login stored for one UID: the file is indexed by UID, an empty slot is "
                    "not evidence the account never logged in, and a program that does not update lastlog leaves it unchanged. Pass "
                    "passwd (the evidence's own) to name the accounts: without it no account is named, and this analysis machine's "
                    "own passwd file is never used.",
        })
        selected = stats["scope"] == "selected UIDs"
        complete = whole or (selected and stats.get("stopped") is None)
        basis_complete = ("every slot of the file was read" if whole else "the slots of the UIDs named were read: the rest of the file was not asked for")
        basis_partial = "the walk stopped at max_seconds or max_slots (next_uid), or the file ends in a short tail: the answer says where"
    else:
        try:
            found = survey(path, size, min(5.0, seconds / 4))
            if order_arg == "auto":
                order, order_basis = decide_byte_order(found)
                if order == "neither":
                    fail("this does not read as a utmp file: %s. If it is a wtmp, btmp or utmp from a C library whose records are not "
                         "384 bytes, this tool does not read it" % order_basis, path=path, bytes=size)
                if order == "ambiguous":
                    fail("the byte order is ambiguous: the records read as utmp in either order. Pass byte_order: little or big",
                         ambiguous=True, candidates=["big", "little"], path=path, basis=order_basis)
            else:
                order, order_basis = order_arg, "argument"
            share = None
            if found["nonempty"]:
                share = found["ok"]["big" if order == "big" else "little"] / found["nonempty"]
            doubt = share is not None and share < SHARE_FLOOR
            if doubt and layout_arg != "utmp-384" and order_arg == "auto":
                fail("this does not read as 384-byte utmp records: only %d of %d non-empty records sampled have a ut_type of 1-9 in %s order. "
                     "The records may be another size (another C library's, a 64-bit time field) or the file may be damaged. If you know they "
                     "are 384 bytes, pass layout: utmp-384 (or a byte_order) to read them anyway." % (found["ok"]["big" if order == "big" else "little"], found["nonempty"], order),
                     path=path, bytes=size, layout_doubt=True)
            out["layout"] = {"name": "utmp-384", "record_bytes": RECORD,
                             "basis": "argument" if layout_arg != "auto" else "assumed: the only utmp layout this tool reads, 384-byte records",
                             "abi": "glibc struct utmp with 32-bit session and time fields",
                             "byte_order": order, "byte_order_basis": order_basis,
                             "type_check": {"non_empty_sampled": found["nonempty"], "with_ut_type_1_to_9": found["ok"]["big" if order == "big" else "little"],
                                            "share": share, "floor": SHARE_FLOOR, "doubt": doubt}}
            parse_utmp(path, size, order, typed, args, pattern, wanted, page, text_file, preview_text, preview_rows, limit, stats, deadline, start_record)
        except OSError as exc:
            fail("the file could not be read: %s" % describe(exc), path=path)
        stopped = stats.get("stopped_at_record")
        whole = size % RECORD == 0 and stopped is None and start_record == 0 and not (out["layout"]["type_check"]["doubt"])
        out.update({
            "records_in_file": stats["records"],
            "empty_records": stats["empty"],
            "by_type": stats["by_type"],
            "boots": stats["boots"],
            "start_record": start_record,
            "stopped_at_record": stopped,
            "stopped_because": stats.get("stopped_because"),
            "trailing_bytes": size % RECORD,
            "trailing_offset": (size // RECORD) * RECORD if size % RECORD else None,
            "all_records_read": whole,
            "user_is_typed": typed,
            "filter_touched_withheld_text": touches_withheld_text(bool(pattern) and typed),
            "note": "A USER_PROCESS record is a session that started; the matching DEAD_PROCESS on the same line is when it ended, and a "
                    "session with no end is not shown to be still open. btmp holds failures and its user field is what was typed, which "
                    "may be no account and can be a password typed into the wrong field: in btmp the name is not in the answer, only "
                    "its length (user_bytes), and is in the text file. Records exist only for programs that wrote them: a missing record "
                    "is not a login that did not happen. A type outside 0-9 is UNKNOWN, kept raw. Compare these records with auth.log and "
                    "the journal; a disagreement has more than one explanation (rotation, a program that does not write wtmp, a damaged "
                    "or edited file).",
        })
        complete = whole
        basis_complete = ("every record of the file was read, but every record is empty, so no byte order is supported by them (byte_order is undetermined)"
                          if order == "undetermined" else "every record of the file was read, in a byte order the records support")
        basis_partial = "the read stopped at max_seconds (stopped_at_record), the file ends in a short tail, it starts after record 0, or its records do not all read as utmp: the answer says which"
    text_file.close()
    pages = {"records": page.finish()}
    capped = capped_why(pages, text_file)
    if capped:
        complete, basis_partial = False, (basis_partial + "; " if basis_partial else "") + capped
    outcome = status_of(complete, False, basis_complete, basis_partial, "")
    out.update({**outcome, "passwd": stats["passwd"], "text": text_file.summary(preview_text),
                "record_count": pages["records"]["matched"], "records": preview_rows if preview_text else page.page, "pages": pages,
                "truncated": pages["records"]["truncated"]})
    hold_stop_signals()
    STATE["answering"] = True
    print(json.dumps(out, indent=2))


if __name__ == "__main__":
    exit_code = 0
    try:
        main()
    except SystemExit as stop:
        exit_code = _code(stop)
    _leave(exit_code)
