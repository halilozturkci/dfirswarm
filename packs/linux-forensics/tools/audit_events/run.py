#!/usr/bin/env python3
"""Read the Linux audit log (auditd's audit.log and its rotations) with the standard library and group its records into events.

auditd writes one text line per record: `type=SYSCALL msg=audit(1700000000.123:456): arch=c000003e syscall=59 ...`. The
`audit(<seconds>.<milliseconds>:<serial>)` stamp is the event's id: every record of one event (SYSCALL, EXECVE, CWD, PATH,
PROCTITLE, ...) carries the same stamp. This tool reads an explicit, ORDERED list of acquired files (audit.log.2.gz,
audit.log.1, audit.log: the caller's order is the rotation order), streams each (gzip is read as a stream, with a cap on
what it expands to), and groups the records by their stamp, in a window that also spans the boundary between two files, so
an event whose records fall on both sides of a rotation is one group. Where the stamp alone would not do, the tool says so:

  * the serial number restarts after a reboot or an auditd restart (auditd(8), audit.log(5)), so a stamp is not unique over
    a long log: the group window is bounded, and a serial that falls while time does not is counted and located as a
    `serial_reset`; a stamp seen again after its group was closed is a new group (`continued_group`), counted;
  * time that goes backwards (a clock set back, a rotation given in the wrong order) is reported as runs of records below
    the highest time seen so far (`time_regressions`), with the file and line where each run starts;
  * a gap in the rotation numbers the caller gave (audit.log.1 and audit.log.3 but no .2) is named: a missing rotation bounds
    every negative drawn from the rest.

Facts this tool relies on, from audit.log(5), ausearch(8), audit.rules(7) and the auditd record dictionary:
  * a value with a space or a control character is written as hexadecimal text, unquoted (`exe=2F62696E2F6C73`); a plain
    value is quoted or bare. PROCTITLE is the hexadecimal text of argv with NUL between the arguments.
  * `auid=4294967295` (-1 as an unsigned 32-bit number) is the audit uid that was never set.
  * EXECVE writes `argc=N` and one `aK=` per argument; an argument too long for one field is split as `aK_len=` and
    `aK[0]=`, `aK[1]=`, ... (audit.log(5)).
  * a SYSCALL record's `success=yes|no` is the result of that system call, not of the command that made it. `items=N` is the
    number of PATH records the event should carry.
  * `lost=` in the status and daemon records is a counter of events the kernel dropped; the rule set, the backlog and the
    rotations the caller collected all bound what is absent.
  * with `log_format = ENRICHED` auditd appends, after an ASCII group separator (0x1d), upper-case `KEY=value` pairs
    (interpreted names) that the logging host resolved when it wrote the record; they are kept beside the originals.

What the answer shows: the record types of each group, their file, line and byte offset, the counts and lengths of the
command lines (argc, the length of each argument, the length of PROCTITLE), the numeric and enumerated fields of the
grammar (a fixed list in SHOWN), and the missing parts of an event. It never shows a command line, an `exe`, a `cwd`, a
PATH name, an account name that was typed or any other free text, nor a hash or a fragment of one: those are lengths. The
whole of every line goes to audit-text.jsonl, mode 0600, only on `write_text` in a job run as secret output.

A second reader, `compare_ausearch`, runs the declared `ausearch` on a sample (the first 2000 lines of the first file) and says `agree`,
`disagree` or `not_run`, with the differences counted and never their text. It runs only in a job that was run as secret output (the
sample is a copy of evidence text, 0600 under $OUT, removed afterwards), only after the installed `ausearch` has returned a probe record
through `-if <file> -r` (the file-input contract, checked on the installed version and recorded), never with `-i` (which would name
users through this machine's passwd and group), and as a program of this tool's own process group: a deadline, a stop signal or an
output past the cap ends it and what it started.

The identity map (`identity`: passwd and group files of the EVIDENCE) names uids and gids; without it they stay numeric. This
analysis machine's /etc/passwd and /etc/group are never read.
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
import ipaddress
import json
import math
import os
import re
import secrets
import select
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
import zlib
from collections import OrderedDict
from pathlib import Path

TOOL = "audit_events"
PARSER = "audit_events/9"


DEFAULT_LIMIT = 100
DEFAULT_SECONDS = 120.0
MAX_SECONDS = 240.0          # the most a caller may ask for (the manifest allows 300)
TEXT_NAME = "audit-text.jsonl"
RECEIPT_NAME = "receipt.json"
MAX_PATHS = 1000             # files in one call
MAX_PATH_CHARS = 4096
MAX_LINE = 1 << 20           # a line longer than this is counted and located, not parsed (audit lines are a few KiB at most)
BLOCK = 1 << 20              # bytes handled at a time
MAX_EXPANDED = 4 << 30       # one gzip file stops expanding here
WINDOW = 256                 # groups kept open at once, so records of one event that are not adjacent still meet
MAX_GROUP_RECORDS = 256      # records kept per group; more are counted
MAX_TOKENS = 2000            # fields read per record; more is a parse error on that record
MAX_IDENTITY = 8 << 20       # one identity file
MAX_IDENTITY_NAMES = 200000
CLOCK_LINES = 16             # the clock is read at least this often, in lines (a line is at most MAX_LINE bytes)
FIRST_FAILURES = 20
MAX_NODES = 100
MAX_TYPES = 1000
MAX_ARG_LENGTHS = 64
EPOCH = datetime.datetime(1970, 1, 1)
UNSET = 4294967295
GS = "\x1d"
SAMPLE_LINES = 2000          # lines of the first file that the second reader is given
SAMPLE_BYTES = 4 << 20
SECOND_CAP = 32 << 20        # ausearch's output kept for the comparison; more ends it
SECOND_SECONDS = 30.0        # the most the second reader may take
PROBE = (b"type=USER_START msg=audit(1000000000.001:1): pid=1 uid=0 auid=1000 ses=1 msg='op=probe res=success'\n")

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
# program runs each stream has a running cap too (STDOUT_CAP 64 MiB, STDERR_CAP 8 MiB with its head and last STDERR_TAIL 1 MiB kept, or the
# caller's `caps`): past it the program is ended on the deadline's own path (kill_tree, its tree only), the stream comes back cut
# (Output.cut, output_cut()), OUTPUT_CUT counts the call and process_apply turns a complete answer partial; a caller that parses a cut
# output says so and never takes it for a whole one.
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


def _same_ident(pid, before, listed):
    """Whether `pid` is still the process `before` was read from. `listed` is the identity the table just read gave it: when it is the same
    kind of identity (a start time from /proc, from libproc or from ps) the two are compared; when it is not (macOS: a process is seen
    through libproc and listed through ps, and the two give different texts for one start time) the pid is read again the way `before` was."""
    if listed is not None and listed[0] == before[0]:
        return listed == before
    return same_process(pid, before)


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
            if before is not None and not _same_ident(pid, before, listed):
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
        if pid in table and (table[pid] is None or (table[pid] == ident if ident is None or table[pid][0] == ident[0] else same_process(pid, table[pid]))):
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
        if row is None or not _same_ident(pid, SEEN_IDENT[pid], listed) or row[0] == me:
            continue
        parent = row[0]
        if parent in table and SEEN_IDENT.get(parent) is not None and _same_ident(parent, SEEN_IDENT[parent], table.ident.get(parent)):
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
    a call of communicate_bounded that was cut at POST_EXIT_BYTES counts, PIPE_CUT, and so does one that ended a program whose output passed
    its running cap, OUTPUT_CUT): what a program wrote while the tool read it, or what it printed past a cap, is not a complete result. A
    carrier calls it once where it prints its answer. Returns `answer`."""
    verdict = process_verdict()
    answer["program_group"] = verdict
    if (verdict["left_behind"] > 0 or verdict["unproven"] or PIPE_CUT["cut"] or OUTPUT_CUT["cut"]) and answer.get("status") == "complete":
        answer["status"] = "partial"
        for flag in ("ok", "complete"):
            if flag in answer:
                answer[flag] = False
        if verdict["left_behind"] > 0:
            sentence = "a program left %d process%s running after it ended; the tool ended them, and what they wrote before that is in the files named here" % (
                verdict["left_behind"], "" if verdict["left_behind"] == 1 else "es")
        elif OUTPUT_CUT["cut"]:
            sentence = "a program's output was not read whole: %s" % OUTPUT_CUT["last"]
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
STDOUT_CAP = 64 << 20        # the most bytes of standard output one call of communicate_bounded keeps; past it the program is ended and the output is cut
STDERR_CAP = 8 << 20         # the most bytes of standard error one call reads before it ends the program; it keeps the head and the last STDERR_TAIL bytes
STDERR_TAIL = 1 << 20        # the tail of standard error kept once it passes STDERR_CAP (a program's last words are at its end)
OUTPUT_CUT = {"cut": 0, "last": None}    # how many calls cut a stream at its running cap, and the sentence of the last one


class Output(bytes):
    """What communicate_bounded kept of one stream: the bytes, and `cut`, None when the stream was read whole, or a sentence saying it was
    not (the program printed past the stream's cap and was ended there). A caller that parses the output reads `cut` first: a cut output
    is never a whole one."""
    cut = None


def output_cut(*outputs):
    """The sentence of the first of `outputs` (values communicate_bounded or preflight returned) that was cut at its cap; None when each was
    read whole."""
    for out in outputs:
        text = getattr(out, "cut", None)
        if text:
            return text
    return None


def _output(data, cut):
    out = Output(data)
    out.cut = cut
    return out


def communicate_bounded(proc, seconds, input=None, caps=None):
    """(stdout bytes, stderr bytes, timed out) for a program started with pipes, in bytes (Output: bytes with a `cut` sentence or None). At
    `seconds` the program and what it started are killed (timed out). What the tool holds is capped while the program runs: `caps` is
    (stdout cap, stderr cap), STDOUT_CAP and STDERR_CAP when it is None. Standard output is kept to its cap; standard error keeps its head and
    its last STDERR_TAIL bytes (at most half its cap). When either stream passes its cap the program and what it started are ended (kill_tree,
    the deadline's own path: its tree, nothing else), what was kept is returned with `cut` set on that stream, the call is counted in
    OUTPUT_CUT and said in process_notes(), and process_apply turns a complete answer partial. A program that has ended while something it
    started still holds its pipes (a daemon, a helper that inherited them) does not hold the tool: from the moment the program has ended (or
    was killed) the pipes are given PIPE_GRACE seconds and POST_EXIT_BYTES bytes, whichever is used up first; what the program wrote is kept,
    what the tool lost is killed (reap_orphans, settle), and the pipes are let go. A cut at the byte cap is counted in PIPE_CUT and noted
    (process_notes()); the return shape is the same. The pipes are read here and by nothing else (not by Popen.communicate), so letting them
    go is safe. `input` is written while the program runs and is dropped once it has ended."""
    deadline = time.monotonic() + max(0.1, seconds)
    out_cap, err_cap = (STDOUT_CAP, STDERR_CAP) if caps is None else (max(0, int(caps[0])), max(0, int(caps[1])))
    tail_keep = min(STDERR_TAIL, err_cap // 2)
    bufs = (bytearray(), bytearray())       # standard output; the head of standard error
    tail = bytearray()                      # the last tail_keep bytes of standard error read past its head
    seen, over = [0, 0], [False, False]     # bytes read from each stream; the stream passed its cap while the program ran
    late = [False, False]                   # the stream passed its cap after the program had ended (by itself, or at the deadline)
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
    timed_out, note, ended, extra, cut, sampled, ended_at_cap = False, None, None, 0, False, 0.0, False
    try:
        while True:
            now = time.monotonic()
            if ended is None:
                if proc.poll() is not None:
                    ended = now
                elif over[0] or over[1]:
                    ended_at_cap = True
                    note = kill_tree(proc)
                    ended = time.monotonic()
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
                index = key.data
                seen[index] += len(data)
                if ended is not None:
                    extra += len(data)
                if index == 0:
                    room = out_cap - len(bufs[0])
                    if room > 0:
                        bufs[0].extend(data[:room])
                    if seen[0] > out_cap:
                        over[0], late[0] = (over[0], True) if ended is not None else (True, late[0])
                else:
                    room = err_cap - tail_keep - len(bufs[1])
                    if room > 0:
                        bufs[1].extend(data[:room])
                        data = data[room:]
                    if data:
                        tail.extend(data)
                        if len(tail) > tail_keep:
                            del tail[:len(tail) - tail_keep]
                    if seen[1] > err_cap:
                        over[1], late[1] = (over[1], True) if ended is not None else (True, late[1])
                if (over[0] or over[1]) and ended is None:
                    break           # the loop's head ends the program at once
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
    # A stream that passed its cap only after the program had ended is cut too, unless the pipes were cut at POST_EXIT_BYTES: then what passed
    # it is a process that held the pipe and went on writing, PIPE_CUT says so, and the program's own output was read whole.
    for index in (0, 1):
        over[index] = over[index] or (late[index] and not cut)
    ending = "; the tool ended the program there" if ended_at_cap else ""
    out_cut = ("the program printed more than %d bytes on its standard output; the tool kept the first %d and did not read the rest%s" % (
        out_cap, len(bufs[0]), ending)) if over[0] else None
    err_cut = ("the program printed more than %d bytes on its standard error; the tool kept the first %d and the last %d%s" % (
        err_cap, len(bufs[1]), len(tail), ending)) if over[1] else None
    for sentence in (out_cut, err_cut):
        if sentence:
            OUTPUT_CUT["cut"] += 1
            OUTPUT_CUT["last"] = sentence
            _note(sentence)
    err = bytes(bufs[1])
    if over[1]:
        err += b"\n[... %d bytes of standard error not kept ...]\n" % (seen[1] - len(bufs[1]) - len(tail))
    err += bytes(tail)
    if note:
        err = err + (b"\n" if err else b"") + note.encode("utf-8", "replace")
    return _output(bufs[0], out_cut), _output(err, err_cut), timed_out     # (one copy of standard output, not two)


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
    if "answer_a_stop" in globals():     # (a block run on its own, by a test, has no ENDS block)
        answer_a_stop(signum)
    os._exit(128 + signum)


def preflight(argv, seconds, caps=None):
    """Run a short program, bounded; (exit code or None, stdout bytes, stderr bytes, timed out). The outputs are communicate_bounded's (Output,
    held to `caps`): a program ended because a stream passed its cap has that stream's `cut` set (output_cut()) and its own exit code."""
    try:
        proc = spawn(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except OSError as exc:
        return None, _output(b"", None), _output(describe(exc).encode("utf-8", "replace"), None), False
    ACTIVE.append(proc)
    try:
        out, err, timed_out = communicate_bounded(proc, max(1.0, seconds), caps=caps)
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


# This tool's stop is the SHARED PROCESS block above, which has no deferral of a signal during a write; the parts above are written for
# the stop of LINUX STOP and need these two names (which here do nothing) and these keys of STATE.
STATE.update({"pages": [], "text": None, "writing": 0, "pending": None, "answering": False, "stopping": False})


def _writing():
    STATE["writing"] += 1


def _written():
    STATE["writing"] -= 1
    if not STATE["writing"] and STATE["pending"] is not None:
        signum, STATE["pending"] = STATE["pending"], None
        _on_signal(signum, None)


def audit_on_signal(signum, frame):
    """The process block's stop, held while a paging or text row is being written (Python can run a handler inside a buffered file's own
    write, and the last word's flush of that file is then refused) and while the answer is being written: the signal is noted and the
    write gives the stop when it is done."""
    if STATE["answering"] and not STATE["stopping"]:
        return
    if STATE["writing"]:
        STATE["pending"] = signum
        return
    _on_signal(signum, frame)


def install_audit_signal_handlers():
    for signum in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(signum, audit_on_signal)


def audit_last_word(signum):
    """One JSON document naming what the tool had written when a stop signal came (the process block has already ended the programs)."""
    STATE["answering"] = STATE["stopping"] = True
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
    sys.stdout.write(json.dumps({
        "parser": PARSER, "status": "failed", "stopped_by_signal": signum,
        "status_basis": "this tool was stopped by signal %d before it finished: no answer was built, and what it had read is not a complete result" % signum,
        "paging_files_kept": kept, "paging_files_not_flushed": unflushed, "text_file_kept": text_file,
        "text_file_close_error": getattr(text, "close_error", None),
        "kept_note": "the rows each file holds were written in the order read, up to where the tool was stopped; the files are named here and nowhere else",
    }) + "\n")
    sys.stdout.flush()


STATE["last_word"] = audit_last_word
install_audit_signal_handlers()

HEADER = re.compile(r"(?:node=([^ \x00]{1,255}) )?type=([A-Za-z0-9_\[\]]{1,64}) msg=audit\(([0-9]{1,12})\.([0-9]{1,6}):([0-9]{1,12})\):? ?")
KEY = re.compile(r"[A-Za-z_][A-Za-z0-9_\[\].-]{0,63}")
NUM = re.compile(r"(?:-?[0-9]{1,20}|unset)")
HEXNUM = re.compile(r"[0-9a-fA-F]{1,16}")
ENUM = re.compile(r"[A-Za-z0-9_.:()-]{1,48}")
MODE = re.compile(r"[0-7]{1,12}")
DEV = re.compile(r"[0-9a-fA-F]{1,8}:[0-9a-fA-F]{1,8}")
ROTATION = re.compile(r"\.([0-9]{1,6})(?:\.gz)?$")

# The grammar: the keys whose values are shown, and the shape a value must have to be shown. A value that does not have the shape
# is a length, like every key that is not here. (audit.log(5) for the keys; the shapes are narrower than the record dictionary.)
SHOWN = {
    "pid": NUM, "ppid": NUM, "uid": NUM, "gid": NUM, "euid": NUM, "suid": NUM, "fsuid": NUM, "egid": NUM, "sgid": NUM, "fsgid": NUM,
    "auid": NUM, "ses": NUM, "oldauid": NUM, "old-auid": NUM, "old-ses": NUM, "syscall": NUM, "exit": NUM, "items": NUM, "argc": NUM,
    "inode": NUM, "ouid": NUM, "ogid": NUM, "item": NUM, "lost": NUM, "backlog": NUM, "backlog_limit": NUM, "audit_enabled": NUM,
    "audit_pid": NUM, "rate_limit": NUM, "old": NUM, "new": NUM, "sig": NUM, "seq": NUM,
    "arch": HEXNUM, "success": ENUM, "res": ENUM, "tty": ENUM, "nametype": ENUM, "op": ENUM, "key": ENUM, "ver": ENUM, "format": ENUM,
    "state": ENUM, "mode": MODE, "dev": DEV,
}
# Keys the grammar knows and whose values are free text or may be a secret: only their length is shown.
WITHHELD = {"exe", "cwd", "name", "comm", "acct", "hostname", "proctitle", "subj", "terminal", "msg", "grp", "cmd", "data", "dir",
            "path", "addr", "saddr", "laddr", "uri", "id", "obj", "profile", "table", "unit", "scontext", "tcontext", "pathname",
            "ino", "cap_fp", "cap_fi", "cap_fe", "cap_fver", "cap_pe", "cap_pi", "cap_pp", "cap_pa",
            "old_prom", "prom", "grantors", "reason", "rport", "lport", "net", "daddr", "sport", "dport", "sig_pid"}
ENRICHED_SHOWN = {"ARCH": ENUM, "SYSCALL": ENUM, "AUID": re.compile(r"[A-Za-z0-9_.@$-]{1,64}"), "UID": re.compile(r"[A-Za-z0-9_.@$-]{1,64}"),
                  "GID": re.compile(r"[A-Za-z0-9_.@$-]{1,64}"), "EUID": re.compile(r"[A-Za-z0-9_.@$-]{1,64}"),
                  "SUID": re.compile(r"[A-Za-z0-9_.@$-]{1,64}"), "FSUID": re.compile(r"[A-Za-z0-9_.@$-]{1,64}"),
                  "EGID": re.compile(r"[A-Za-z0-9_.@$-]{1,64}"), "SGID": re.compile(r"[A-Za-z0-9_.@$-]{1,64}"),
                  "FSGID": re.compile(r"[A-Za-z0-9_.@$-]{1,64}")}
UID_KEYS = ("auid", "uid", "euid", "suid", "fsuid")
GID_KEYS = ("gid", "egid", "sgid", "fsgid")
# The system call numbers of execve and execveat for the two architectures this tool names (auditd's arch field, hexadecimal).
EXEC_CALLS = {"c000003e": (59, 322), "c00000b7": (221, 281)}
LIMITS_NOTE = ("An absent event is not shown to be an event that did not happen: auditd records only what its rules select, the kernel "
               "drops events when its backlog is full (see lost_counters), a rotation the caller did not collect is not read (see "
               "rotation_gaps), and a log can be edited or removed. A SYSCALL's success is the result of that system call, not of the "
               "command. auid 4294967295 is an audit uid that was never set. A serial restarts after a reboot or an auditd restart.")


def want_paths(args):
    value = args.get("paths")
    if not isinstance(value, list) or not value:
        fail("paths is required: a non-empty list of the audit files in rotation order (oldest first), as the caller names them")
    if len(value) > MAX_PATHS:
        fail("paths holds %d files; at most %d are read in one call" % (len(value), MAX_PATHS))
    out = []
    for item in value:
        out.append(want_path_value(item, "paths"))
    return out


def want_path_value(item, what):
    if not isinstance(item, str) or not item:
        fail("%s must hold non-empty strings" % what)
    if len(item) > MAX_PATH_CHARS:
        fail("a path in %s is longer than %d characters" % (what, MAX_PATH_CHARS))
    if "\x00" in item:
        fail("a path in %s holds a NUL" % what)
    try:
        os.fsencode(item)
    except (UnicodeEncodeError, ValueError):
        fail("a path in %s is not a name a file can have (a lone surrogate)" % what)
    return item


def want_zone_time(args, key):
    """An instant with its zone written out (Z or +hh:mm): a bound without a zone would be read in the zone of the machine running this."""
    value = args.get(key)
    if value is None:
        return None
    if not isinstance(value, str) or len(value) > 40:
        fail("%s must be a date and time with its zone, such as 2026-02-14T09:30:00Z or 2026-02-14T11:30:00+02:00" % key)
    if not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}[T ][0-9]{2}:[0-9]{2}(?::[0-9]{2}(?:\.[0-9]{1,6})?)?(?:Z|[+-][0-9]{2}:[0-9]{2})", value):
        fail("%s must be a date and time with its zone, such as 2026-02-14T09:30:00Z or 2026-02-14T11:30:00+02:00 (no zone is not read as UTC)" % key)
    try:
        moment = datetime.datetime.fromisoformat(value)
        if moment.tzinfo is None:
            raise ValueError("no zone")
        return (moment - datetime.datetime(1970, 1, 1, tzinfo=datetime.timezone.utc)).total_seconds()
    except (ValueError, OverflowError, OSError):
        fail("%s is not a valid date and time with a zone" % key)


def iso(sec, frac):
    """ISO 8601 in UTC with the fraction the record wrote (its digits, as written), or None where the date is past the calendar."""
    try:
        base = EPOCH + datetime.timedelta(seconds=sec)
    except (OverflowError, ValueError):
        return None
    return base.strftime("%Y-%m-%dT%H:%M:%S") + "." + frac + "Z"


def iso_float(stamp):
    whole = int(stamp)
    return iso(whole, "%03d" % min(999, int(round((stamp - whole) * 1000))))


class Clock:
    """The one deadline: every walk and every phase after a read asks it, so no phase runs past max_seconds."""

    def __init__(self, seconds):
        self.deadline = time.monotonic() + seconds
        self.out = False

    def expired(self):
        if time.monotonic() >= self.deadline:
            self.out = True
        return self.out


def open_regular(path):
    """(fd, size) of a regular file, opened without blocking and without following a link at the last component; or an OSError."""
    fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0))
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise OSError("not a regular file: a pipe, a socket or a device is never read")
        return fd, info.st_size
    except BaseException:
        os.close(fd)
        raise


def check_inputs(paths, key):
    """Refuse, before anything is read, a path that is not a regular file, a link or a disk image."""
    for path in paths:
        try:
            info = os.lstat(path)
        except OSError as exc:
            fail("%s cannot be read: %s" % (key, describe(exc)), path=path)
        if stat.S_ISLNK(info.st_mode):
            fail("refusing a symlink: pass the file inside the evidence", path=path)
        if not stat.S_ISREG(info.st_mode):
            fail("not a regular file: a pipe, a socket or a device is never opened", path=path)
        refuse_disk_image(path, "path")


def blocks(fd, state, clock):
    """The decompressed stream of one file in pieces of at most BLOCK bytes. A gzip file is read as a stream (members one after
    another) and stops at MAX_EXPANDED; a damaged one stops where zlib says so (state['error'])."""
    head = os.read(fd, 2)
    state["gzip"] = head == b"\x1f\x8b"
    os.lseek(fd, 0, os.SEEK_SET)
    if not state["gzip"]:
        while True:
            if clock.expired():
                return
            data = os.read(fd, BLOCK)
            if not data:
                return
            yield data
    inflater = None
    while True:
        if clock.expired():
            return
        raw = os.read(fd, 1 << 18)
        if not raw:
            if inflater is not None and not inflater.eof:
                state["error"] = "the gzip stream ends before its end marker (a truncated file)"
            return
        pending = raw
        while pending:
            if inflater is None:
                if pending[:2] != b"\x1f\x8b":
                    state["trailing"] += len(pending)
                    pending = b""
                    break
                inflater = zlib.decompressobj(31)
            try:
                out = inflater.decompress(pending, BLOCK)
            except zlib.error as exc:
                state["error"] = "the gzip stream is damaged (%s)" % str(exc)[:60]
                return
            state["expanded"] += len(out)
            if state["expanded"] > MAX_EXPANDED:
                state["error"] = "the file expanded past %d bytes and was not read further" % MAX_EXPANDED
                state["capped"] = True
                return
            if out:
                yield out
            if inflater.eof:
                pending = inflater.unused_data
                inflater = None
            else:
                pending = inflater.unconsumed_tail
            if clock.expired():
                return


def split_lines(fd, state, clock):
    """(line number, byte offset in the decompressed stream, bytes without the newline, length). A line over MAX_LINE is yielded as
    (n, offset, None, length): it is never held in memory."""
    lineno = 0
    pieces, size = [], 0
    line_start = 0
    over, over_len = False, 0
    for block in blocks(fd, state, clock):
        at = 0
        base = state["base"]
        while True:
            nl = block.find(b"\n", at)
            if nl < 0:
                tail = len(block) - at
                if over:
                    over_len += tail
                elif tail:
                    if size + tail > MAX_LINE:
                        over, over_len = True, size + tail
                        pieces, size = [], 0
                    else:
                        pieces.append(block[at:])
                        size += tail
                break
            lineno += 1
            seg_len = nl - at
            if over:
                yield lineno, line_start, None, over_len + seg_len
                over, over_len = False, 0
            elif size + seg_len > MAX_LINE:
                yield lineno, line_start, None, size + seg_len
            else:
                pieces.append(block[at:nl])
                yield lineno, line_start, b"".join(pieces), size + seg_len
            pieces, size = [], 0
            at = nl + 1
            line_start = base + at
        state["base"] = base + len(block)
    if over:
        yield lineno + 1, line_start, None, over_len
    elif pieces:
        yield lineno + 1, line_start, b"".join(pieces), size


def tokenize(rest):
    """key=value pairs of one record: a value is "quoted", 'quoted' (a userspace message) or bare, up to the next space. Linear, with a cap.
    Returns (pairs, stray, cut, unterminated)."""
    pairs, stray, cut, unterminated = [], 0, False, False
    i, n = 0, len(rest)
    while i < n:
        if rest[i] == " ":
            i += 1
            continue
        if len(pairs) + stray >= MAX_TOKENS:
            cut = True
            break
        sp = rest.find(" ", i)
        eq = rest.find("=", i, n if sp < 0 else sp)
        if eq < 0:
            stray += 1
            i = n if sp < 0 else sp + 1
            continue
        key = rest[i:eq]
        i = eq + 1
        if i < n and rest[i] in "\"'":
            quote = rest[i]
            end = rest.find(quote, i + 1)
            if end < 0:
                unterminated = True
                value, quoted, i = rest[i + 1:], quote, n
            else:
                value, quoted, i = rest[i + 1:end], quote, end + 1
        else:
            sp = rest.find(" ", i)
            end = n if sp < 0 else sp
            value, quoted, i = rest[i:end], "", end
        if not KEY.fullmatch(key):
            stray += 1
            continue
        pairs.append((key, value, quoted))
    return pairs, stray, cut, unterminated


def is_hex_text(value):
    return len(value) >= 2 and len(value) % 2 == 0 and not value.strip("0123456789ABCDEFabcdef")


def value_bytes(value, quoted, may_be_hex):
    """(length in bytes, hex encoded) of a field's value: hexadecimal text of the keys that auditd encodes is its decoded length."""
    if not quoted and may_be_hex and is_hex_text(value):
        return len(value) // 2, True
    return blen(value), False


def load_identity(paths, clock):
    """Names from the evidence's own passwd and group files: {'uid': {n: [names]}, 'gid': {n: [names]}}, and what was read of each."""
    users, groups, files = {}, {}, []
    for path in paths:
        info = {"path": path, "kind": None, "entries": 0, "bytes": 0, "malformed_lines": 0, "read": False}
        files.append(info)
        try:
            fd, size = open_regular(path)
        except OSError as exc:
            info["error"] = describe(exc)
            continue
        try:
            if size > MAX_IDENTITY:
                info["error"] = "larger than %d bytes: not read" % MAX_IDENTITY
                continue
            data = b""
            while len(data) <= size and not clock.expired():
                part = os.read(fd, 1 << 20)
                if not part:
                    break
                data += part
            info["bytes"] = len(data)
            for number, line in enumerate(decode(data).split("\n")):
                if number % 4096 == 0 and clock.expired():
                    info["error"] = "max_seconds passed while this file was read"
                    break
                line = line.rstrip("\r")
                if not line or line.startswith("#"):
                    continue
                fields = line.split(":")
                if len(fields) == 7 and fields[2].isdigit() and len(fields[2]) < 12:
                    kind, table, number_ = "passwd", users, int(fields[2])
                elif len(fields) == 4 and fields[2].isdigit() and len(fields[2]) < 12:
                    kind, table, number_ = "group", groups, int(fields[2])
                else:
                    info["malformed_lines"] += 1
                    continue
                if info["kind"] not in (None, kind):
                    info["kind"] = "mixed"
                else:
                    info["kind"] = kind
                info["entries"] += 1
                if sum(len(v) for v in table.values()) < MAX_IDENTITY_NAMES:
                    table.setdefault(number_, []).append(fields[0])
            info["read"] = "error" not in info
        except OSError as exc:
            info["error"] = describe(exc)
        finally:
            os.close(fd)
    return {"uid": users, "gid": groups}, files


class Group:
    def __init__(self, key, sec, ms, serial, node, loc):
        self.key = key
        self.sec, self.ms, self.serial, self.node = sec, ms, serial, node     # ms: the fraction's digits as written
        self.first = loc
        self.last = loc
        self.files = [loc["file"]]
        self.records = []
        self.records_over = 0
        self.types = []
        self.type_counts = {}
        self.errors = []
        self.syscall = None
        self.execve = None
        self.proctitle = None
        self.cwd_bytes = None
        self.paths = []
        self.items = None
        self.continued = False
        self.serial_reset = None
        self.regression = False
        self.enriched = None
        self.arch = None
        self.syscall_no = None
        self.span_bytes = 0


def parse_record(m, line, loc, errors, decoded=None):
    """The record's shown fields, its withheld lengths and its parts that other records of the event need. `line` is the whole text."""
    typ = m.group(2)
    rest = line[m.end():]
    enriched_raw = None
    if GS in rest:
        rest, enriched_raw = rest.split(GS, 1)
    pairs, stray, cut, unterminated = tokenize(rest)
    inner_pairs = []
    for key, value, quoted in pairs:
        if key == "msg" and quoted == "'":
            sub, sub_stray, sub_cut, sub_unterminated = tokenize(value)
            inner_pairs.extend(sub)
            stray += sub_stray
            cut = cut or sub_cut
            unterminated = unterminated or sub_unterminated
    pairs = [p for p in pairs if not (p[0] == "msg" and p[2] == "'")] + inner_pairs
    rec = {"type": typ, "file": loc["file"], "line": loc["line"], "offset": loc["offset"], "bytes": loc["bytes"], "fields": {},
           "withheld_bytes": {}, "other_fields": 0, "other_bytes": 0, "hex_encoded": 0}
    seen = set()
    duplicates = 0
    parts = {"args": {}, "execve_argc": None, "proctitle": None, "cwd": None, "name": None, "arch": None}
    for key, value, quoted in pairs:
        if key in seen:
            duplicates += 1
            continue
        seen.add(key)
        base = key
        shape = SHOWN.get(key)
        if typ == "EXECVE" and re.fullmatch(r"a[0-9]{1,6}(?:_len|\[[0-9]{1,6}\])?", key):
            index = int(re.match(r"a([0-9]+)", key).group(1))
            slot = parts["args"].setdefault(index, {"len": None, "pieces": {}, "bytes": 0, "hex": False})
            if decoded is not None and not key.endswith("_len") and not quoted and is_hex_text(value):
                decoded[key] = decode(bytes.fromhex(value))
            if key.endswith("_len"):
                slot["len"] = int(value) if value.isdigit() and len(value) < 12 else None
            else:
                length, was_hex = value_bytes(value, quoted, True)
                if key.endswith("]"):
                    slot["pieces"][int(key[key.index("[") + 1:-1])] = length
                else:
                    slot["pieces"][0] = length
                slot["hex"] = slot["hex"] or was_hex
                rec["hex_encoded"] += 1 if was_hex else 0
            continue
        if shape is not None and not quoted == "'" and len(value) <= 64 and shape.fullmatch(value) and not (key in ("key", "op") and quoted == "" and is_hex_text(value) and len(value) > 24):
            rec["fields"][key] = value
            if key == "arch":
                parts["arch"] = value.lower()
            continue
        if key == "addr" and not quoted:
            try:
                ipaddress.ip_address(value)
                rec["fields"]["addr"] = value
                continue
            except ValueError:
                pass
        length, was_hex = value_bytes(value, quoted, key in WITHHELD)
        if was_hex:
            rec["hex_encoded"] += 1
            if decoded is not None:
                raw_value = bytes.fromhex(value)
                decoded[key] = [decode(piece) for piece in raw_value.rstrip(b"\x00").split(b"\x00")] if key == "proctitle" else decode(raw_value)
        if key in WITHHELD:
            rec["withheld_bytes"][key] = length
            if key == "proctitle":
                parts["proctitle"] = (value, quoted, was_hex)
            elif key == "cwd":
                parts["cwd"] = length
            elif key == "name":
                parts["name"] = length
        else:
            rec["other_fields"] += 1
            rec["other_bytes"] += length
    if duplicates:
        rec["duplicate_fields"] = duplicates
    problems = []
    if stray:
        problems.append("%d token(s) that are not key=value" % stray)
    if cut:
        problems.append("more than %d fields: the rest of the line is not read" % MAX_TOKENS)
    if unterminated:
        problems.append("a quote is not closed")
    if problems:
        rec["errors"] = problems
        errors.extend("%s: %s" % (typ, p) for p in problems)
    if enriched_raw is not None:
        shown, hidden = {}, 0
        for key, value, quoted in tokenize(enriched_raw)[0]:
            shape = ENRICHED_SHOWN.get(key)
            if shape is not None and not quoted and shape.fullmatch(value):
                shown[key] = value
            else:
                hidden += 1
        rec["enriched"] = {"shown": shown, "other_fields": hidden}
    return rec, parts


def add_to_group(group, rec, parts, identity):
    typ = rec["type"]
    group.last = {"file": rec["file"], "line": rec["line"], "offset": rec["offset"]}
    if rec["file"] not in group.files:
        group.files.append(rec["file"])
    if typ in group.type_counts or len(group.type_counts) < MAX_GROUP_RECORDS:
        group.type_counts[typ] = group.type_counts.get(typ, 0) + 1
    if len(group.records) < MAX_GROUP_RECORDS:
        group.records.append(rec)
        group.types.append(typ)
    else:
        group.records_over += 1
    for message in rec.get("errors", ()):
        if len(group.errors) < 20:
            group.errors.append(message)
    if typ == "SYSCALL" and group.syscall is None:
        group.syscall = rec["fields"]
        group.arch = parts["arch"]
        group.syscall_no = int(rec["fields"]["syscall"]) if rec["fields"].get("syscall", "x").isdigit() else None
        if rec["fields"].get("items", "x").isdigit():
            group.items = int(rec["fields"]["items"])
    elif typ == "EXECVE" and group.execve is None:
        argc = rec["fields"].get("argc")
        args = parts["args"]
        lengths, split, incomplete, hexed = [], 0, 0, 0
        for index in sorted(args)[:100000]:
            slot = args[index]
            total = sum(slot["pieces"].values())
            if len(slot["pieces"]) > 1:
                split += 1
            if slot["len"] is not None and slot["len"] != total:
                incomplete += 1
            if slot["hex"]:
                hexed += 1
            if len(lengths) < MAX_ARG_LENGTHS:
                lengths.append(slot["len"] if slot["len"] is not None and len(slot["pieces"]) > 1 else total)
        group.execve = {"argc": int(argc) if argc and argc.isdigit() else None, "args_found": len(args), "arg_bytes": lengths,
                        "arg_bytes_cut": len(args) > MAX_ARG_LENGTHS, "split_args": split, "incomplete_args": incomplete, "hex_args": hexed}
    elif typ == "PROCTITLE" and group.proctitle is None and parts["proctitle"] is not None:
        value, quoted, was_hex = parts["proctitle"]
        if was_hex:
            size = len(value) // 2
            whole = bytes.fromhex(value)
            group.proctitle = {"bytes": size, "argc": (whole.count(0) + (0 if whole.endswith(b"\x00") else 1)) if size else 0, "hex": True}
        else:
            group.proctitle = {"bytes": blen(value), "argc": 1 if value else 0, "hex": False}
    elif typ == "CWD" and group.cwd_bytes is None:
        group.cwd_bytes = parts["cwd"]
    elif typ == "PATH":
        group.paths.append({k: rec["fields"][k] for k in ("item", "nametype", "mode", "ouid", "ogid", "dev", "inode") if k in rec["fields"]}
                           | {"name_bytes": parts["name"]})
    if "enriched" in rec and group.enriched is None:
        group.enriched = rec["enriched"]


def finish_group(group, identity):
    missing = []
    if group.syscall is not None and group.items is not None and len(group.paths) < group.items:
        missing.append({"component": "PATH", "why": "the SYSCALL says items=%d and %d PATH record(s) are in the group" % (group.items, len(group.paths))})
    if group.execve is not None and group.execve["argc"] is not None and group.execve["args_found"] < group.execve["argc"]:
        missing.append({"component": "EXECVE arguments", "why": "EXECVE says argc=%d and %d argument field(s) are in the record" % (group.execve["argc"], group.execve["args_found"])})
    if group.execve is not None and group.execve["incomplete_args"]:
        missing.append({"component": "EXECVE argument pieces", "why": "%d split argument(s) whose pieces do not add up to their aK_len" % group.execve["incomplete_args"]})
    calls = EXEC_CALLS.get(group.arch or "")
    if group.syscall is not None and calls and group.syscall_no in calls and group.execve is None:
        missing.append({"component": "EXECVE", "why": "an execve system call of this architecture with no EXECVE record in the group (the rule may not log arguments, or the record was lost)"})
    if group.syscall is not None and group.proctitle is None and (group.execve is not None or (calls and group.syscall_no in calls)):
        missing.append({"component": "PROCTITLE", "why": "an execution with no PROCTITLE record (not every kernel writes one)"})
    row = {"event": group.key, "time_raw": "%d.%s" % (group.sec, group.ms), "time": iso(group.sec, group.ms),
           "serial": group.serial, "node": group.node, "first": group.first, "last": group.last, "files": group.files,
           "types": group.types, "type_counts": group.type_counts, "records": group.records, "records_not_kept": group.records_over,
           "syscall": group.syscall, "execve": group.execve, "proctitle": group.proctitle, "cwd_bytes": group.cwd_bytes, "paths": group.paths[:64],
           "paths_not_kept": max(0, len(group.paths) - 64), "missing_components": missing, "parse_errors": group.errors,
           "continued_group": group.continued, "serial_reset": group.serial_reset, "time_regression": group.regression, "enriched": group.enriched}
    if group.syscall is not None:
        names = {}
        for key in UID_KEYS + GID_KEYS:
            value = group.syscall.get(key)
            if value is None:
                continue
            entry = {"raw": value}
            if key in ("auid", "uid", "euid", "suid", "fsuid", "gid", "egid", "sgid", "fsgid") and value.lstrip("-").isdigit():
                number = int(value)
                if key == "auid" and number in (UNSET, -1):
                    entry["unset"] = True
                elif identity is not None:
                    found = identity["uid" if key in UID_KEYS else "gid"].get(number)
                    if found:
                        entry["names"] = sorted(set(found))[:5]
            names[key] = entry
        row["identity"] = names
        row["syscall_success_means"] = "the system call's result, not the command's"
    return row


def row_text(rec_text, loc, key, typ, decoded=None):
    row = {"file": loc["file"], "line": loc["line"], "offset": loc["offset"], "event": key, "type": typ, "text": rec_text}
    if decoded:
        row["decoded"] = decoded      # hexadecimal values decoded, beside the original text
    return row


def run_read(paths, wanted, since, until, page, text_file, identity, clock, stats, sample=None):
    """Read every file in the caller's order. Groups close as the window moves, and at the end of the last file."""
    exact = {w for w in wanted if not w.endswith("*")}
    prefixes = tuple(w[:-1] for w in wanted if w.endswith("*"))
    window = OrderedDict()
    flushed = OrderedDict()
    state = {"prev": None, "high": None, "run": None}

    def emit(group):
        row = finish_group(group, identity)
        stats["events"] += 1
        low = group.sec + int(group.ms) / 10 ** len(group.ms)
        if since is not None and low < since or until is not None and low >= until:
            stats["outside_time_range"] += 1
            return
        if wanted and not any(t in exact or t.startswith(prefixes) for t in group.type_counts):
            stats["outside_types"] += 1
            return
        stats["matched"] += 1
        page.add(row)

    def push_out():
        while len(window) > WINDOW:
            _, old = window.popitem(last=False)
            flushed[old.key] = None
            if len(flushed) > 100000:
                flushed.popitem(last=False)
            emit(old)

    def close_run():
        run, state["run"] = state["run"], None
        if run is not None:
            stats["regression_runs"].append(run)

    for index, path in enumerate(paths):
        info = {"index": index, "path": path, "bytes": None, "compressed": False, "expanded_bytes": 0, "lines": 0, "records": 0,
                "blank_lines": 0, "unparsed_lines": 0, "oversize_lines": 0, "nul_lines": 0, "crlf_lines": 0, "bad_utf8_lines": 0,
                "enriched_records": 0, "first_time": None, "last_time": None, "first_line_time_raw": None, "last_line_time_raw": None,
                "rotation_number": None, "read": "not_started", "error": None}
        stats["files"].append(info)
        m = ROTATION.search(path)
        if m:
            info["rotation_number"] = int(m.group(1))
        if clock.expired():
            info["error"] = "max_seconds passed before this file was reached"
            continue
        try:
            fd, size = open_regular(path)
        except OSError as exc:
            info["read"], info["error"] = "failed", describe(exc)
            continue
        info["bytes"] = size
        fstate = {"gzip": False, "expanded": 0, "base": 0, "error": None, "capped": False, "trailing": 0}
        first_ts = last_ts = None
        counted = 0
        try:
            for lineno, offset, raw, length in split_lines(fd, fstate, clock):
                counted += 1
                if counted % CLOCK_LINES == 0 and clock.expired():
                    break
                info["lines"] = lineno
                loc = {"file": index, "line": lineno, "offset": offset, "bytes": length}
                if raw is None:
                    info["oversize_lines"] += 1
                    stats["oversize"].append({**loc, "why": "longer than %d bytes: located and not parsed" % MAX_LINE})
                    continue
                if raw.endswith(b"\r"):
                    raw = raw[:-1]
                    info["crlf_lines"] += 1
                if sample is not None and index == 0 and sample["lines"] < SAMPLE_LINES and sample["bytes"] + len(raw) < SAMPLE_BYTES:
                    sample["raw"].append(raw + b"\n")
                    sample["lines"] += 1
                    sample["bytes"] += len(raw) + 1
                if not raw.strip():
                    info["blank_lines"] += 1
                    continue
                if b"\x00" in raw:
                    info["nul_lines"] += 1
                try:
                    line = raw.decode("utf-8")
                except UnicodeDecodeError:
                    line = decode(raw)
                    info["bad_utf8_lines"] += 1
                header = HEADER.match(line[:700])
                if header is None:
                    info["unparsed_lines"] += 1
                    stats["unparsed"].append({**loc, "why": "not an audit record (no type=... msg=audit(...) header)"})
                    text_file.add(row_text(line, loc, None, None))
                    continue
                frac = header.group(4)
                sec, serial = int(header.group(3)), int(header.group(5))
                key = "%s.%s:%d" % (header.group(3), frac, serial)
                node = header.group(1)
                decoded = {} if text_file.enabled else None
                rec, parts = parse_record(header, line, loc, [], decoded)
                info["records"] += 1
                if "enriched" in rec:
                    info["enriched_records"] += 1
                if rec["type"] in stats["by_type"] or len(stats["by_type"]) < MAX_TYPES:
                    stats["by_type"][rec["type"]] = stats["by_type"].get(rec["type"], 0) + 1
                else:
                    stats["by_type_other"] += 1
                if node is not None:
                    if node in stats["nodes"] or len(stats["nodes"]) < MAX_NODES:
                        stats["nodes"][node] = stats["nodes"].get(node, 0) + 1
                    else:
                        stats["nodes_not_listed"] += 1
                stamp = sec + int(frac) / 10 ** len(frac)
                if first_ts is None:
                    first_ts, info["first_line_time_raw"] = stamp, "%d.%s" % (sec, frac)
                last_ts, info["last_line_time_raw"] = stamp, "%d.%s" % (sec, frac)
                text_file.add(row_text(line, loc, key, rec["type"], decoded))
                if "lost" in rec["fields"] or rec["type"].startswith("DAEMON_"):
                    stats["counters"].append({"type": rec["type"], "event": key, "file": index, "line": lineno, "time": iso(sec, frac),
                                              **{k: rec["fields"][k] for k in ("lost", "backlog", "backlog_limit", "audit_enabled", "audit_pid", "ver", "format", "res", "auid", "pid") if k in rec["fields"]}})
                group = window.get(key)
                if group is None:
                    group = Group(key, sec, frac, serial, node, {"file": index, "line": lineno, "offset": offset})
                    if key in flushed:
                        group.continued = True
                        stats["continued_groups"] += 1
                    prev = state["prev"]
                    if prev is not None and serial < prev[0] and stamp >= prev[1]:
                        group.serial_reset = {"from_serial": prev[0], "to_serial": serial}
                        stats["serial_resets"].append({"event": key, "file": index, "line": lineno, "offset": offset, "from_serial": prev[0], "to_serial": serial,
                                                       "time": iso(sec, frac)})
                    state["prev"] = (serial, stamp)
                    high = state["high"]
                    if high is not None and stamp < high:
                        group.regression = True
                        run = state["run"]
                        if run is None:
                            run = state["run"] = {"file": index, "line": lineno, "offset": offset, "groups": 0, "highest_before": iso_float(high), "backwards_seconds": 0.0}
                        run["groups"] += 1
                        run["backwards_seconds"] = max(run["backwards_seconds"], round(high - stamp, 3))
                    else:
                        close_run()
                        state["high"] = stamp
                    window[key] = group
                    push_out()
                else:
                    window.move_to_end(key)
                add_to_group(group, rec, parts, identity)
        except OSError as exc:
            fstate["error"] = fstate["error"] or "read failed: %s" % describe(exc)
        finally:
            os.close(fd)
        info["compressed"] = fstate["gzip"]
        info["expanded_bytes"] = fstate["base"]
        info["gzip_trailing_bytes"] = fstate["trailing"] or None
        if first_ts is not None:
            info["first_time"], info["last_time"] = iso_float(first_ts), iso_float(last_ts)
        info["first_stamp"], info["last_stamp"] = first_ts, last_ts
        if fstate["error"]:
            info["read"], info["error"] = "partial", fstate["error"]
        elif clock.out:
            info["read"], info["error"] = "partial", "max_seconds passed while this file was read (stopped near line %d)" % info["lines"]
        else:
            info["read"] = "complete"
        if clock.out:
            stats["stopped"] = {"file": index, "line": info["lines"]}
            break
    close_run()
    for group in list(window.values()):
        emit(group)
    window.clear()


def rotation_inventory(files):
    """Gaps between the files in the caller's order, and in the rotation numbers the file names carry."""
    gaps, overlaps = [], []
    numbered = sorted({f["rotation_number"] for f in files if f["rotation_number"] is not None})
    missing = []
    if numbered:
        have = set(numbered)
        for n in range(1, min(numbered[-1], 100000) + 1):
            if n not in have and len(missing) < 50:
                missing.append(n)
    previous = None
    for f in files:
        if f.get("first_stamp") is None:
            continue
        if previous is not None:
            delta = f["first_stamp"] - previous["last_stamp"]
            entry = {"after_file": previous["index"], "next_file": f["index"], "seconds": round(delta, 3)}
            if delta < 0:
                entry["why"] = "this file starts before the one before it ends: the order given is not time order, or the files overlap"
                overlaps.append(entry)
            else:
                gaps.append(entry)
        previous = f
    return gaps, overlaps, missing


def program_group_problems(what, held=True):
    """Sentences for the answer's problems from the shared process block's verdict, for an answer that reports `what`. A process settle() ended means what the program
    wrote (or printed on a pipe it held) was cut where it was ended; where the absence of one cannot be proven (not Linux, PR_SET_CHILD_SUBREAPER refused) files a program
    wrote cannot be shown to be final. held=False is a tool that reports only what a program printed on a pipe: it is not held to the second rule (program_group still
    says why), but processes that were adopted and could not all be ended are still named."""
    verdict = process_verdict()
    found = []
    if verdict["left_behind"]:
        found.append("a program left %d process(es) running after it ended (in the tool's process group, in a session of its own, or after a double fork); the shared process block "
                     "stopped, killed and reaped them before %s were read, so what they would still have written is missing from %s%s" % (
            verdict["left_behind"], what, what, "" if held else ", and the lines they wrote into the pipe before that cannot be told from the program's: the rows, counts or table of this run are not to be trusted"))
    for why in verdict["unproven"]:
        if held or verdict["subreaper"]:
            found.append("%s: %s cannot be shown to be final" % (why, what))
    # a pipe cut at its byte cap is a fact whatever the host: a process that held the pipe after the program ended went on writing, and what it wrote is mixed into the bytes the
    # program printed (no leftover need have been found: on a host that cannot adopt orphans none is). PIPE_CUT is one count for the run, a version probe's included.
    # an output cut at its running cap (OUTPUT_CUT, a count for the run): the program was ended there and what it printed was not read whole
    if OUTPUT_CUT["cut"]:
        found.append("a program's output was not read whole: %s" % OUTPUT_CUT["last"])
    if PIPE_CUT["cut"]:
        found.append("a process that held a program's pipe after the program ended went on writing: the tool read no more than %d bytes of it and let the pipe go, so %s may contain bytes the program did not write (the cut is counted once for the whole run: a cut while the program's version was read makes the answer partial)" % (POST_EXIT_BYTES, "the program's version line (read on a pipe through the shared process block)"))
    return found


def read_bounded(proc, seconds, cap):
    """(stdout bytes, timed out, over the cap) of a program started with spawn: read with select, with a deadline and a cap; a program that
    ended while something it started holds the pipe is given PIPE_GRACE seconds and what it left behind is ended (reap_orphans)."""
    deadline = time.monotonic() + seconds
    chunks, size, timed_out, over, exited, release = [], 0, False, False, None, None
    fd = proc.stdout.fileno()
    while True:
        now = time.monotonic()
        if now >= deadline:
            timed_out = True
            if proc.poll() is not None:
                settle()        # the program had ended: what holds the pipe is a leftover, counted (program_group.left_behind) as it is ended
            kill_tree(proc)
            reap_orphans(_pipe_inodes(proc))
            break
        if release is not None and now >= release:
            break               # the holder was ended and the pipe still has no end: it is let go
        if exited is None and proc.poll() is not None:
            exited = now        # counted from the program's end whether bytes keep coming or not: a leftover that writes slowly does not hold the tool
        if release is None and exited is not None and now - exited >= PIPE_GRACE:
            reap_orphans(_pipe_inodes(proc))
            settle()            # a process that holds the pipe is ended (program_group.left_behind), and the pipe gets its end
            release = time.monotonic() + 1.0
        _sample(proc.pid)
        ready, _w, _x = select.select([fd], [], [], max(0.01, min(0.2, deadline - now)))
        if ready:
            chunk = os.read(fd, 1 << 20)
            if not chunk:
                break
            size += len(chunk)
            if size > cap:
                over = True
                if proc.poll() is not None:
                    settle()    # the program had ended: what floods the pipe is a leftover, counted as it is ended
                kill_tree(proc)
                reap_orphans(_pipe_inodes(proc))
                break
            chunks.append(chunk)
    return b"".join(chunks), timed_out, over


def ausearch_run(exe, args, seconds):
    """(exit code or None, stdout bytes, timed out, over the cap). The program is ours: its own group, no stdin, no stderr, a sane environment."""
    env = {"PATH": os.environ.get("PATH", "/usr/sbin:/usr/bin:/sbin:/bin"), "LC_ALL": "C"}
    proc = spawn([exe] + args, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=env)
    ACTIVE.append(proc)
    try:
        out, timed_out, over = read_bounded(proc, seconds, SECOND_CAP)
    finally:
        if proc.poll() is None:
            try:
                proc.wait(timeout=PIPE_GRACE)    # a program that closed its pipe is still exiting: its leftover is still its child, and the kill of the tree below would end it uncounted
            except subprocess.TimeoutExpired:
                pass
        if proc.poll() is None:
            kill_tree(proc)
        try:
            proc.stdout.close()
        except OSError:
            pass
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            pass
        ACTIVE.remove(proc)
    return (None if timed_out or over else proc.returncode), out, timed_out, over


def keys_of(data):
    """{(event id, record type): count} of the audit records in a program's output; a line that is not a record is counted apart."""
    seen, other = {}, 0
    for raw in data.split(b"\n"):
        if not raw.strip():
            continue
        m = HEADER.match(decode(raw)[:700])
        if m is None:
            other += 1
            continue
        key = (m.group(3) + "." + m.group(4) + ":" + m.group(5), m.group(2))
        seen[key] = seen.get(key, 0) + 1
    return seen, other


def second_reader(sample, seconds):
    """Run ausearch on the sample and compare it with what the standard-library reader saw in the same lines. The comparison is of
    (event id, record type) counts; a difference is counted and its text is never shown."""
    result = {"status": "not_run", "reader": "ausearch -if <sample> -r", "interpretation": "never (-i is not used: it would name users through this machine's passwd and group)"}
    exe = shutil.which("ausearch")
    if exe is None:
        result["why"] = "ausearch is not installed here (apt: auditd)"
        return result
    mine, _ignored = keys_of(b"".join(sample["raw"])) if sample is not None else ({}, 0)
    if not mine:
        result["why"] = "the first file holds no audit record to sample"
        return result
    if seconds < 4:
        result["why"] = "no time was left for it"
        return result
    start = time.monotonic()
    code, out, _err, timed_out = preflight([exe, "--version"], 5, caps=(1 << 16, 1 << 16))
    version = re.sub(r"[^\x20-\x7e]", "?", " ".join((out + _err).decode("latin-1").split()))[:80]
    result["version"] = version or None
    if output_cut(out, _err):
        # the version text past its cap is not taken; ausearch is still run (the cut is said through program_group_problems, and the answer is partial)
        result["version"] = version = None
        result["version_not_read"] = "ausearch printed past its cap when asked for its version and was ended: %s" % output_cut(out, _err)
    elif timed_out or code is None or not version:
        result["why"] = "the installed ausearch did not print a version within 5 seconds"
        return result
    directory = None
    try:
        base = os.environ.get("OUT")
        directory = tempfile.mkdtemp(prefix=".ausearch-", dir=base)
        os.chmod(directory, 0o700)
        probe, sample_file = os.path.join(directory, "probe.log"), os.path.join(directory, "sample.log")
        for path, data in ((probe, PROBE), (sample_file, b"".join(sample["raw"]))):
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
            with os.fdopen(fd, "wb") as fh:
                fh.write(data)
        left = lambda: seconds - (time.monotonic() - start)    # noqa: E731
        code, out, timed_out, over = ausearch_run(exe, ["-if", probe, "-r"], min(10.0, max(1.0, left())))
        probe_seen, _ = keys_of(out)
        if code not in (0, None) or timed_out or over or probe_seen != {("1000000000.001:1", "USER_START"): 1}:
            result["why"] = ("the installed ausearch did not return the probe record through -if <file> -r (exit %s%s): the file-input contract is not confirmed "
                             "for this version, and the sample was not run" % (code, ", timed out" if timed_out else ""))
            result["contract_confirmed"] = False
            return result
        result["contract_confirmed"] = True
        if left() < 2:
            result["why"] = "no time was left for the sample after the probe"
            return result
        code, out, timed_out, over = ausearch_run(exe, ["-if", sample_file, "-r"], min(SECOND_SECONDS, max(1.0, left())))
        result["exit_code"] = code
        if timed_out or over:
            result["why"] = "ausearch %s" % ("did not finish within its time" if timed_out else "wrote more than %d bytes; it was ended" % SECOND_CAP)
            return result
        if code not in (0, 1):
            result["why"] = "ausearch ended with exit code %s (0 is a match, 1 is no match; nothing else is read as an answer)" % code
            return result
        theirs, not_records = keys_of(out)
        only_mine = sum(max(0, n - theirs.get(k, 0)) for k, n in mine.items())
        only_theirs = sum(max(0, n - mine.get(k, 0)) for k, n in theirs.items())
        events_mine, events_theirs = {k[0] for k in mine}, {k[0] for k in theirs}
        result.update({"status": "agree" if not (only_mine or only_theirs) else "disagree",
                       "sample": {"file": 0, "lines": sample["lines"], "bytes": sample["bytes"], "records": sum(mine.values()), "events": len(events_mine)},
                       "ausearch": {"records": sum(theirs.values()), "events": len(events_theirs), "lines_that_are_not_records": not_records},
                       "differences": {"records_only_here": only_mine, "records_only_in_ausearch": only_theirs,
                                       "events_only_here": len(events_mine - events_theirs), "events_only_in_ausearch": len(events_theirs - events_mine)},
                       "note": "the comparison is of (event id, record type) counts over the sample; the text of a difference is never shown"})
        return result
    except OSError as exc:
        result["why"] = "the sample could not be prepared: %s" % describe(exc)
        return result
    finally:
        if directory is not None:
            shutil.rmtree(directory, ignore_errors=True)


def main():
    args = read_args()
    paths = want_paths(args)
    identity_paths = []
    if args.get("identity") is not None:
        value = args["identity"]
        if not isinstance(value, list) or not value or len(value) > 8:
            fail("identity must be a list of one to eight passwd or group files of the evidence")
        identity_paths = [want_path_value(item, "identity") for item in value]
    wanted = {t.upper() for t in want_str_list(args, "types")}
    if len(wanted) > 100 or any(len(t) > 70 for t in wanted):
        fail("types holds at most 100 record types of at most 70 characters")
    since, until = want_zone_time(args, "since"), want_zone_time(args, "until")
    if since is not None and until is not None and since >= until:
        fail("since must be before until")
    limit = want_limit(args)
    write_text = want_flag(args, "write_text")
    compare = want_flag(args, "compare_ausearch")
    if compare:
        require_job("compare_ausearch")
    seconds = want_seconds(args, "max_seconds", DEFAULT_SECONDS, MAX_SECONDS)
    reserve = min(SECOND_SECONDS + 5.0, seconds * 0.4) if compare else 0.0
    total_deadline = time.monotonic() + seconds
    clock = Clock(seconds - reserve)
    check_inputs(paths, "paths")
    check_inputs(identity_paths, "identity")
    try:
        text_file = TextFile(TEXT_NAME, write_text, "JSON Lines, mode 0600: every line of the files read, whole, with its file, line, offset, event id and record type", flag="write_text")
    except TextRefused as exc:
        fail(str(exc))
    STATE["text"] = text_file
    page = LosslessPage(TOOL, "events", limit)
    names, identity_files = None, []
    if identity_paths:
        names, identity_files = load_identity(identity_paths, clock)
    stats = {"files": [], "events": 0, "matched": 0, "outside_time_range": 0, "outside_types": 0, "by_type": {}, "by_type_other": 0, "nodes": {},
             "nodes_not_listed": 0, "continued_groups": 0, "serial_resets": Listed("serial_resets"), "regression_runs": Listed("time_regression_runs"),
             "oversize": Listed("oversize_lines"), "unparsed": Listed("unparsed_lines"), "counters": Listed("lost_and_daemon_records"), "stopped": None}
    sample = {"raw": [], "lines": 0, "bytes": 0} if compare else None
    run_read(paths, wanted, since, until, page, text_file, names, clock, stats, sample)
    text_file.close()
    if not compare:
        second = {"status": "not_run", "why": "not asked for (compare_ausearch: true runs the installed ausearch on a sample of the first file, in a job run as secret output)"}
    elif clock.out:
        second = {"status": "not_run", "why": "the read stopped at max_seconds before the sample was complete"}
    else:
        second = second_reader(sample, total_deadline - time.monotonic() - 1.0)
    files = stats["files"]
    gaps, overlaps, missing_numbers = rotation_inventory(files)
    inventory = Listed("files")
    for f in files:
        inventory.append({k: v for k, v in f.items() if k not in ("first_stamp", "last_stamp")})
    totals = {k: sum(f[k] for f in files) for k in ("lines", "records", "blank_lines", "unparsed_lines", "oversize_lines", "nul_lines", "crlf_lines", "bad_utf8_lines", "enriched_records")}
    read_all = all(f["read"] == "complete" for f in files) and not clock.out
    lines_ok = totals["unparsed_lines"] == 0 and totals["oversize_lines"] == 0
    pages = {"events": page.finish()}
    listed = {}
    for key, items in (("serial_resets", stats["serial_resets"]), ("time_regression_runs", stats["regression_runs"]), ("oversize_lines", stats["oversize"]),
                       ("unparsed_lines", stats["unparsed"]), ("lost_and_daemon_records", stats["counters"]), ("files", inventory)):
        pages[key] = items.settle()
        listed[key] = {"total": items.page.total, "shown": list(items)}
    parts = []
    # ausearch (the second reader) reports what it printed on a pipe: a process it left behind (ended by settle() before its output was compared) makes the comparison one that
    # cannot be trusted, so the answer is partial; the files this tool reads are its own, so a host that cannot adopt orphans does not make it partial (program_group says why)
    group = program_group_problems("the second reader's output", held=False)
    if not read_all:
        bad = [f["index"] for f in files if f["read"] != "complete"]
        parts.append("file(s) %s were not read to their end (see rotation_inventory)" % ", ".join(str(i) for i in bad[:20]) if bad else "max_seconds passed")
    if not lines_ok:
        parts.append("%d line(s) are not audit records and %d line(s) over %d bytes were located and not parsed" % (totals["unparsed_lines"], totals["oversize_lines"], MAX_LINE))
    capped = capped_why(pages, text_file)
    if capped:
        parts.append(capped)
    identity_complete = all(f["read"] for f in identity_files)
    if identity_files and not identity_complete:
        parts.append("an identity file was not read: its ids stay numeric")
    parts.extend(group)
    outcome = status_of(read_all and lines_ok and not capped and identity_complete and not group, False,
                        "every line of every file given was read and parsed, in the order given", "; ".join(parts) or "partial", "")
    out = {"parser": PARSER, **outcome, "all_lines_parsed": lines_ok, "all_files_read": read_all,
           "paths_given": len(paths), "files_read": sum(1 for f in files if f["read"] == "complete"),
           "totals": totals, "events_total": stats["events"], "events_matched": stats["matched"],
           "filters": {"types": sorted(wanted), "since": args.get("since"), "until": args.get("until"),
                       "outside_types": stats["outside_types"], "outside_time_range": stats["outside_time_range"],
                       "note": "types and the time range filter the events listed (events_matched); events_total and the counts are over every event read"},
           "by_type": dict(sorted(stats["by_type"].items())), "by_type_other_records": stats["by_type_other"],
           "nodes": stats["nodes"], "nodes_not_listed": stats["nodes_not_listed"], "continued_groups": stats["continued_groups"],
           "serial_resets": listed["serial_resets"], "time_regression_runs": listed["time_regression_runs"],
           "oversize_lines": listed["oversize_lines"], "unparsed_lines": listed["unparsed_lines"],
           "lost_and_daemon_records": listed["lost_and_daemon_records"],
           "rotation_inventory": {"files": listed["files"], "gaps_between_files": gaps[:INLINE_LIST], "files_out_of_time_order": overlaps[:INLINE_LIST],
                                  "rotation_gaps": missing_numbers,
                                  "note": "the files are read in the order given; a rotation number missing from the names given (rotation_gaps) was not collected or not passed"},
           "stopped": stats["stopped"],
           "identity": {"given": identity_files, "names_from": "the supplied files only; this machine's /etc/passwd and /etc/group are never read" if identity_files else "none supplied: uids and gids stay numeric"},
           "second_reader": second, "program_group": process_verdict(),
           "text": text_file.summary(), "events": page.page, "pages": pages, "truncated": pages["events"]["truncated"],
           "limits": LIMITS_NOTE}
    if clock.out:
        out["stopped_because"] = "max_seconds"
    out["receipt"] = write_receipt(out)
    hold_stop_signals()
    STATE["answering"] = True
    text = json.dumps(out, indent=2)
    try:
        # a stop signal that comes while the answer is being written must not start a second document: signals are held from here
        signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGTERM, signal.SIGINT, signal.SIGHUP})
    except (AttributeError, ValueError, OSError):
        pass
    print(text, flush=True)


def write_receipt(out):
    """The answer without its events, as a file of its own under $OUT in a job (a name already there is never replaced); None elsewhere."""
    job, base = os.environ.get("JOB_ID"), os.environ.get("OUT")
    if not (job and base):
        return None
    doc = {k: v for k, v in out.items() if k not in ("events", "pages")}
    data = json.dumps(doc, indent=2).encode("utf-8", "backslashreplace") + b"\n"
    name = RECEIPT_NAME
    tmp = None
    try:
        Path(base).mkdir(parents=True, exist_ok=True)
        tmp = os.path.join(base, ".%s-%s" % (RECEIPT_NAME, secrets.token_hex(8)))
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o644)
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        for attempt in range(2):
            target = os.path.join(base, name)
            try:
                os.link(tmp, target)
                break
            except FileExistsError:
                name = "receipt-%s.json" % secrets.token_hex(4)
        else:
            return {"error": "the receipt could not be placed"}
        return "store/jobs/%s/out/%s" % (re.sub(r"[^A-Za-z0-9_.-]", "_", job), name)
    except OSError as exc:
        return {"error": "the receipt could not be written (%s)" % describe(exc)}
    finally:
        if tmp is not None:
            try:
                os.unlink(tmp)
            except OSError:
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


def last_resort(exc):
    """Any exception nobody expected is one JSON document and exit 1: never a traceback. The paging and text files that exist are named."""
    if STATE.get("answering"):
        os._exit(1)
    hold_stop_signals()
    STATE["answering"] = True
    kept = {}
    for page in STATE["pages"]:
        try:
            shown = page.stop_here()
        except BaseException:  # noqa: BLE001
            shown = None
        if shown:
            kept[page.key] = shown
    text = STATE["text"]
    shown_text = getattr(text, "shown", None) if text is not None and getattr(text, "written", 0) else None
    if text is not None:
        try:
            text.close()
        except BaseException:  # noqa: BLE001
            pass
    try:
        sys.stdout.write(json.dumps({"parser": PARSER, "error": "the tool stopped on an unexpected %s" % type(exc).__name__, "status": "failed",
                                     "status_basis": "an internal error ended the tool before it built an answer: nothing here is a complete result",
                                     "paging_files_kept": kept, "text_file_kept": shown_text}) + "\n")
        sys.stdout.flush()
    except BaseException:  # noqa: BLE001
        pass
    os._exit(1)


if __name__ == "__main__":
    exit_code = 0
    try:
        try:
            main()
        except SystemExit:
            raise
        except BaseException as exc:  # noqa: BLE001 - the last resort
            hold_stop_signals(quietly=True)
            last_resort(exc)
    except SystemExit as stop:
        exit_code = _code(stop)
    _leave(exit_code)
