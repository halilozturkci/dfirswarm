#!/usr/bin/env python3
"""List the places a Linux root starts programs from: cron tables, systemd units and their drop-ins and links, rc.local, init.d and XDG autostart.

Every place the tool tried is named with what it found there (a `locations` list: missing, a link not followed, an alias of a
directory already read, read with N entries). From an extracted root it reads:

    cron      etc/crontab, etc/cron.d/*, etc/cron.{hourly,daily,weekly,monthly}/*, var/spool/cron/crontabs/*, var/spool/cron/*
    systemd   system units: etc/systemd/system, usr/lib/systemd/system, lib/systemd/system, usr/local/lib/systemd/system, run/systemd/system
              user units:   etc/systemd/user, usr/lib/systemd/user, usr/local/lib/systemd/user, etc/xdg/systemd/user, and each home's
                            .config/systemd/user and .local/share/systemd/user (an account's home from etc/passwd, and every directory under
                            home/ and root: a deleted account leaves its home behind)
              .service .timer .path .socket units, <unit>.d/*.conf drop-ins, <target>.wants/ and .requires/ links, masks and aliases
    other     etc/rc.local, etc/init.d/*, etc/xdg/autostart/*.desktop and each home's .config/autostart/*.desktop

CONFIGURATION AND EXECUTION ARE KEPT APART. Each entry's `configuration` is what a file says (the lines, with file, line and byte
offset). Its `execution` is `not_attempted` unless the caller names rows that show execution (`execution_rows`: the records file of a
journal_export call, JSON Lines with a `unit` or `user_unit` field): then it counts the rows that name the unit, with the first and last
time, and says nothing about a unit those rows do not name. A listed unit is not evidence that it ran.

THE EFFECTIVE STATE IS NOT RESOLVED, and the answer says why: drop-ins apply in file-name order over the unit file and an empty
assignment resets a list (a drop-in with `ExecStart=` is listed with `resets_list`), the unit search path has an order, a unit can be
masked or aliased by a link, generators write units at boot and transient units exist only at run time, and `systemctl` cannot be
asked about a disk. This tool lists; it does not merge, follow or rebuild. A copy made with target-fs does not keep links: where the
tree shows no link at all the answer says enablement, masks and aliases cannot be read from it.

THE SECRET-SAFE OUTPUT PATTERN (docs/packs.md, "Secrets and sensitive output"). A command line (Exec*=) and an environment
(Environment=, EnvironmentFile=) can hold a secret. The answer carries, per assignment, its line and byte offset, the key's name only
where systemd defines it (any other key name is a length: a line that is no setting puts its first word where a key goes), the value
only for the keys with launch or scheduling meaning (the unit's type, user, group, restart policy, the schedule, the triggers, the
targets it is wanted by, the sockets it listens on) and only when it has the shape of such a value; every other value is a length. An
Exec line is its phase, its prefix flags, its word count and its length; an environment is its length and the number of assignments
in it, and the names of its variables are not printed. The whole text of every line goes to persistence-text.jsonl (mode 0600) only
on `write_text`, in a job run as secret output.
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
#   not printed (3.11 and 3.12 say nothing of it, 3.14 a traceback). A handler that was due runs on the way in, and never raises out of it.
#   Every writer of a final answer calls it before it commits to writing, every error branch at the end calls it, and, when the file runs as
#   a program, standard output is wrapped so that its first write calls it too. _code(stop) is a SystemExit's exit code (its text, if it has
#   one, goes to standard error as the interpreter puts it), and _leave(code) ends the call: both hold the signals first; _leave flushes
#   standard output (a write that fails there makes a 0 an exit 120, as the interpreter does) and standard error, runs the atexit hooks (a hook
#   that removes a temporary file), each step on its own and none able to raise, and ends the process with os._exit, never through the teardown.
# The modules are imported here, as the file is loaded, never inside the ending (an import there ran a due handler inside the import system).
import atexit
import json
import os
import signal
import sys

_ENDING = {"held": False}
_ENDING_SIGNALS = (signal.SIGTERM, signal.SIGINT, signal.SIGHUP)


def answer_a_stop(signum, when="before it had answered"):
    """The one document of a stop that ends the call before any answer was begun (nothing once one has): status failed, interrupted, and
    no claim about what was read or written. A handler whose own last word printed nothing calls it before it ends the process."""
    if _ENDING["held"]:
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


def hold_stop_signals():
    """Hold the stop signals for good. Never raises. Called by a thread that is not the main one, it blocks them there and leaves the rest to
    the main thread's next call."""
    for _attempt in range(len(_ENDING_SIGNALS) + 2):
        if _ENDING["held"]:
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
        except BaseException:  # noqa: BLE001 - a handler that was due ran on the way in (and raised): the hold is made again
            continue


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
    hold_stop_signals()
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
    hold_stop_signals()
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
    for _signum in _ENDING_SIGNALS:
        signal.signal(_signum, _stopped_without_handler)
    if sys.stdout is not None and not isinstance(sys.stdout, _AnswerStream):
        sys.stdout = _AnswerStream(sys.stdout)
# END SHARED ENDS


import datetime
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
from pathlib import Path

TOOL = "linux_persistence"
PARSER = "linux_persistence/2"


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
    answer_a_stop(signum)
    os._exit(128 + signum)


def install_signal_handlers():
    for signum in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(signum, _on_signal)


install_signal_handlers()
# END LINUX STOP
DEFAULT_LIMIT = 100
DEFAULT_SECONDS = 60.0
MAX_SECONDS = 105.0           # the most a caller may ask for (the manifest allows 120)
TEXT_NAME = "persistence-text.jsonl"
MAX_UNIT_BYTES = 8 << 20      # a unit, drop-in, table or script larger than this is listed and not read
MAX_CONTINUED = 1 << 20       # a logical line joined from continuation lines is cut here (and said)
MAX_SHOWN_ASSIGNMENTS = 40    # assignments of one file kept inline in its entry; all of them are in the assignments page
MAX_LISTED_NAMES = 200000     # the names of one directory that are looked in
MAX_DEPTH = 4
MAX_EXECUTION_ROWS = 2000000
MAX_EXECUTION_UNITS = 100000
MAX_EXECUTION_BYTES = 256 << 20
MAX_NAMED = 50

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

SYSTEM_UNIT_DIRS = ("etc/systemd/system", "usr/lib/systemd/system", "lib/systemd/system", "usr/local/lib/systemd/system", "run/systemd/system")
GLOBAL_USER_UNIT_DIRS = ("etc/systemd/user", "usr/lib/systemd/user", "usr/local/lib/systemd/user", "etc/xdg/systemd/user")
HOME_UNIT_DIRS = (".config/systemd/user", ".local/share/systemd/user")
CRON_FILES = ("etc/crontab",)
CRON_DIRS = ("etc/cron.d", "etc/cron.hourly", "etc/cron.daily", "etc/cron.weekly", "etc/cron.monthly", "var/spool/cron/crontabs", "var/spool/cron")
UNIT_SUFFIXES = (".service", ".timer", ".path", ".socket")
EFFECTIVE_WHY = [
    "drop-ins (<unit>.d/*.conf) apply over the unit file in file-name order, and an empty assignment resets the list it names: this tool lists each and does not merge them",
    "the unit search path is ordered (etc/systemd/system before usr/lib/systemd/system, run/ before both): a unit of the same name in two places is the earlier one's",
    "a mask is a link to /dev/null and an alias a link to another unit: links are listed with their kind and are not followed",
    "generators write units when the system boots and transient units exist only at run time: neither is in a disk",
    "systemctl cannot be asked about a disk: whether a unit is enabled, active or failed is not read here",
]

EXEC_KEYS = {"ExecStart": "start", "ExecStartPre": "start_pre", "ExecStartPost": "start_post", "ExecStop": "stop", "ExecStopPost": "stop_post",
             "ExecReload": "reload", "ExecCondition": "condition"}
ENV_KEYS = {"Environment", "EnvironmentFile", "PassEnvironment", "UnsetEnvironment"}
UNIT_LIST = re.compile(r"[A-Za-z0-9_.@:%\-]{1,255}(?: [A-Za-z0-9_.@:%\-]{1,255}){0,31}")
ACCOUNT = re.compile(r"[A-Za-z_][A-Za-z0-9_.-]{0,63}\$?|[0-9]{1,10}")
SCHEDULE = re.compile(r"[A-Za-z0-9 :.*,/~+\-]{1,200}")
BOOL = re.compile(r"true|false|yes|no|on|off|1|0")
LISTEN = re.compile(r"[A-Za-z0-9_.:/\[\]@%\-]{1,200}")
TRIGGER_PATH = re.compile(r"/[A-Za-z0-9_.@:/*+%\-]{0,200}")
# The keys whose values are shown, with the shape a value must have to be shown (anything else is a length).
SHOWN = {
    "Type": re.compile(r"simple|exec|forking|oneshot|dbus|notify|notify-reload|idle"),
    "Restart": re.compile(r"no|always|on-success|on-failure|on-abnormal|on-abort|on-watchdog"),
    "User": ACCOUNT, "Group": ACCOUNT, "Unit": UNIT_LIST, "WantedBy": UNIT_LIST, "RequiredBy": UNIT_LIST, "UpheldBy": UNIT_LIST, "Also": UNIT_LIST,
    "Alias": UNIT_LIST, "DefaultInstance": UNIT_LIST,
    "OnCalendar": SCHEDULE, "OnBootSec": SCHEDULE, "OnStartupSec": SCHEDULE, "OnActiveSec": SCHEDULE, "OnUnitActiveSec": SCHEDULE,
    "OnUnitInactiveSec": SCHEDULE, "RandomizedDelaySec": SCHEDULE, "AccuracySec": SCHEDULE,
    "Persistent": BOOL, "Accept": BOOL, "RemainAfterExit": BOOL, "MakeDirectory": BOOL, "WakeSystem": BOOL,
    "ListenStream": LISTEN, "ListenDatagram": LISTEN, "ListenSequentialPacket": LISTEN, "ListenFIFO": LISTEN,
    "PathExists": TRIGGER_PATH, "PathExistsGlob": TRIGGER_PATH, "PathChanged": TRIGGER_PATH, "PathModified": TRIGGER_PATH, "DirectoryNotEmpty": TRIGGER_PATH,
}
# The key names systemd defines that are printed (any other name is a length: `abc123=...` is no setting).
KNOWN_KEYS = set(SHOWN) | set(EXEC_KEYS) | ENV_KEYS | {
    "Description", "Documentation", "After", "Before", "Wants", "Requires", "Requisite", "BindsTo", "PartOf", "Conflicts", "OnFailure", "OnSuccess",
    "ConditionPathExists", "ConditionFileNotEmpty", "ConditionHost", "AssertPathExists", "DefaultDependencies", "RefuseManualStart", "StopWhenUnneeded",
    "WorkingDirectory", "RootDirectory", "RestartSec", "TimeoutStartSec", "TimeoutStopSec", "TimeoutSec", "WatchdogSec", "PIDFile", "BusName",
    "NotifyAccess", "KillMode", "KillSignal", "SendSIGKILL", "StandardInput", "StandardOutput", "StandardError", "SyslogIdentifier", "SyslogFacility",
    "UMask", "Nice", "LimitNOFILE", "LimitNPROC", "LimitCORE", "PrivateTmp", "PrivateNetwork", "PrivateDevices", "ProtectSystem", "ProtectHome",
    "NoNewPrivileges", "CapabilityBoundingSet", "AmbientCapabilities", "SupplementaryGroups", "ReadWritePaths", "ReadOnlyPaths", "SuccessExitStatus",
    "RuntimeDirectory", "StateDirectory", "CacheDirectory", "LogsDirectory", "ConfigurationDirectory", "Slice", "Delegate", "MemoryMax", "CPUQuota",
    "TasksMax", "DynamicUser", "SELinuxContext", "AppArmorProfile", "SecureBits", "OOMScoreAdjust", "IOSchedulingClass", "RestrictAddressFamilies",
    "SocketMode", "SocketUser", "SocketGroup", "Service", "Backlog", "KeepAlive", "FreeBind", "Transparent", "Broadcast", "PassCredentials",
    "TriggerLimitIntervalSec", "TriggerLimitBurst", "RuntimeMaxSec", "Sockets", "TimeoutAbortSec", "ExitType", "SuccessAction", "FailureAction",
    "RebootArgument", "CollectMode", "AllowIsolate", "IgnoreOnIsolate", "JobTimeoutSec", "StartLimitIntervalSec", "StartLimitBurst", "StartLimitAction",
    "WantedByTarget", "SendSIGHUP", "FileDescriptorStoreMax", "OOMPolicy", "ProtectKernelModules", "ProtectKernelTunables", "ProtectControlGroups",
    "RestrictNamespaces", "SystemCallFilter", "MemoryDenyWriteExecute", "LockPersonality", "ProtectHostname", "ProtectClock", "ProtectProc",
}
KNOWN_SECTIONS = {"Unit", "Service", "Install", "Timer", "Path", "Socket", "Mount", "Swap", "Slice", "Automount", "Scope"}
DESKTOP_SHOWN = {"Type": re.compile(r"Application|Link|Directory"), "Hidden": BOOL, "NoDisplay": BOOL, "X-GNOME-Autostart-enabled": BOOL,
                 "Terminal": BOOL, "StartupNotify": BOOL}
CRON_USER = re.compile(r"[a-z_][a-z0-9_-]{0,31}\$?")
CRON_FIELD = re.compile(r"[0-9*/,\-]{1,64}|@(?:reboot|yearly|annually|monthly|weekly|daily|midnight|hourly)")
CRON_ASSIGN = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,63}=")


class Overtime(Exception):
    """The inventory ran out of time (max_seconds)."""


def want_paths_list(args, key, most=8):
    value = args.get(key)
    if value is None:
        return []
    if not isinstance(value, list) or len(value) > most or not all(isinstance(x, str) and x and len(x) <= 4096 and "\x00" not in x for x in value):
        fail("%s must be a list of at most %d non-empty path strings" % (key, most))
    for item in value:
        try:
            os.fsencode(item)
        except (UnicodeEncodeError, ValueError):
            fail("%s holds a name a file cannot have (a lone surrogate)" % key)
    return value


def iso_mtime(path):
    try:
        return datetime.datetime.fromtimestamp(os.lstat(path).st_mtime, datetime.timezone.utc).isoformat().replace("+00:00", "Z")
    except (OSError, ValueError, OverflowError):
        return None


def mode_of(path):
    try:
        return "%04o" % (os.lstat(path).st_mode & 0o7777)
    except OSError:
        return None


def inside(root, path):
    try:
        return os.path.commonpath((os.path.realpath(root), os.path.realpath(path))) == os.path.realpath(root)
    except (OSError, ValueError):
        return False


def read_regular(path, limit):
    """(bytes, None) of a regular file of at most `limit` bytes opened without blocking or following a link, or (None, reason)."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0))
    except OSError as exc:
        return None, describe(exc)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            return None, "not a regular file (a pipe, a socket or a device is never read)"
        if info.st_size > limit:
            return None, "%d bytes is larger than the %d this tool reads: read it with another tool" % (info.st_size, limit)
        chunks, size = [], 0
        while size <= limit:
            part = os.read(fd, 1 << 20)
            if not part:
                break
            chunks.append(part)
            size += len(part)
        if size > limit:
            return None, "the file grew past the %d this tool reads while it was read" % limit
        return b"".join(chunks), None
    except OSError as exc:
        return None, describe(exc)
    finally:
        os.close(fd)


def logical_lines(data, run, comment_chars):
    """(first line number, byte offset of the first line, last line number, text) of each logical line of a unit-style file. A line that ends
    in a backslash continues (a comment line does not). Memory holds the file and the line in hand; the clock is read every 4,096 lines."""
    start, number = 0, 0
    size = len(data)
    while start <= size:
        number += 1
        if (number & 4095) == 0:
            run.check()
        end = data.find(b"\n", start)
        if end < 0:
            end = size
        first_no, first_off = number, start
        text = data[start:end].rstrip(b"\r")
        last_no = number
        start = end + 1
        if not text.lstrip().startswith(comment_chars):
            while text.endswith(b"\\") and start <= size:
                end = data.find(b"\n", start)
                if end < 0:
                    end = size
                number += 1
                nxt = data[start:end].rstrip(b"\r")
                start = end + 1
                last_no = number
                if len(text) > MAX_CONTINUED:
                    text = text[:-1]
                    break
                text = text[:-1] + b" " + nxt
        yield first_no, first_off, last_no, decode(text)
        if start > size:
            return


def known_key(name):
    return name in KNOWN_KEYS


def view_assignment(section, key, value):
    """How an assignment is shown: the key's name only where systemd defines it, the value only where the key is in SHOWN and the value has
    its shape, an Exec line as phase, flags, words and length, an environment as length and count. Nothing else of a value or a variable name."""
    item = {}
    if section is None or section in KNOWN_SECTIONS:
        item["section"] = section
    else:
        item["section_bytes"], item["section_withheld"] = blen(section), True
    if not known_key(key):
        item.update({"key_bytes": blen(key), "key_withheld": True, "value_bytes": blen(value), "value_withheld": True})
        return item
    item["key"] = key
    if key in EXEC_KEYS:
        flags = ""
        rest = value
        while rest[:1] in ("-", "@", "+", "!", ":") and len(flags) < 6:
            flags += rest[0]
            rest = rest[1:]
        item["exec"] = {"phase": EXEC_KEYS[key], "prefix_flags": flags, "words": len(value.split()), "bytes": blen(value), "empty": not value.strip()}
        item["resets_list"] = not value.strip()
        item["value_withheld"] = True
    elif key in ENV_KEYS:
        item.update({"value_bytes": blen(value), "value_withheld": True, "empty": not value.strip()})
        item["resets_list"] = not value.strip()
        if key == "Environment":
            item["variables"] = len(value.split()) if value.strip() else 0
        if key == "EnvironmentFile":
            item["optional"] = value.startswith("-")
    elif key in SHOWN and len(value) <= 4096 and SHOWN[key].fullmatch(value.strip()):
        item["value"] = value.strip()
        item["resets_list"] = not value.strip()
    else:
        item.update({"value_bytes": blen(value), "value_withheld": True})
        if not value.strip():
            item["resets_list"] = True
    return item


class Run:
    def __init__(self, root, text, entries, assignments, deadline, seconds):
        self.root, self.text, self.entries, self.assignments = root, text, entries, assignments
        self.deadline, self.seconds = deadline, seconds
        self.locations = LosslessPage(TOOL, "locations", INLINE_LIST)
        self.read_errors, self.walk_errors, self.skipped_links = Listed("read_errors"), Listed("walk_errors"), Listed("links_not_followed")
        self.special, self.unparsed = Listed("not_regular"), Listed("unparsed_lines")
        self.by_state, self.kinds = {}, {}
        self.seen_real = {}
        self.known_users, self.passwd_read = set(), False
        self.links_seen = 0
        self.unit_files = 0
        self.seq = 0
        self.partial_reason = None
        self.home = None                # (home directory, listed in etc/passwd) while a home's directories are read
        self.unit_names = {}            # (manager, name) -> entry id, for the execution rows

    def check(self):
        if time.monotonic() > self.deadline:
            raise Overtime()

    def census(self, rel, state, **extra):
        self.locations.add({"path": rel, "state": state, **extra})
        key = state.split(":")[0].split(" (")[0]
        self.by_state[key] = self.by_state.get(key, 0) + 1

    def entry(self, row):
        self.seq += 1
        row = {"id": "P%06d" % self.seq, "parser": PARSER, **row}
        self.kinds[row["kind"]] = self.kinds.get(row["kind"], 0) + 1
        self.entries.add(row)
        return row

    def error(self, path, reason):
        self.read_errors.append({"file": path, "error": reason})


def walk_names(run, directory):
    names = []
    with os.scandir(directory) as it:
        for number, item in enumerate(it):
            if (number & 1023) == 0:
                run.check()
            if len(names) >= MAX_LISTED_NAMES:
                run.partial_reason = run.partial_reason or "%s holds more than %d names: only the first %d were looked in" % (directory, MAX_LISTED_NAMES, MAX_LISTED_NAMES)
                break
            names.append(item.name)
    return sorted(names)


def link_row(run, path, rel, parent_kind):
    """A link in a unit directory, listed and not followed. Its kind is read from where it sits and where it points."""
    try:
        target = os.readlink(path)
    except OSError as exc:
        run.error(path, describe(exc))
        return
    run.links_seen += 1
    name = os.path.basename(path)
    parent = os.path.basename(os.path.dirname(path))
    if target == "/dev/null":
        kind = "mask"
    elif parent.endswith((".wants", ".requires")):
        kind = "enablement"
    else:
        kind = "alias"
    plain = (target == "/dev/null" or re.fullmatch(r"/(?:etc|usr/lib|lib|usr/local/lib|run)/systemd/(?:system|user)/[A-Za-z0-9@_.:%\-]{1,200}", target)
             or re.fullmatch(r"(?:\.\./){0,4}[A-Za-z0-9@_.:%\-]{1,200}", target))
    row = {"kind": "link", "link_kind": kind, "file": path, "name": name, "wanted_by_directory": parent if kind == "enablement" else None,
           "target": target if plain else None, "target_bytes": blen(target), "target_withheld": not plain,
           "target_is_same_name": os.path.basename(target) == name, "file_modified": iso_mtime(path)}
    if run.home:
        row["home"], row["account_in_passwd"] = run.home
    run.skipped_links.append({"file": path, "link_kind": kind})
    run.entry(row)
    if run.text.enabled:
        run.text.add({"record_type": "link", "file": path, "target": target})


def unit_entry(run, path, manager, dropin_of=None, order=None):
    run.check()
    data, why = read_regular(path, MAX_UNIT_BYTES)
    if data is None:
        run.error(path, why)
        return
    run.unit_files += 1
    shown, count, other = [], 0, 0
    section = None
    resets, execs, wanted_by, unit_type = 0, 0, [], None
    first_entry_id = "P%06d" % (run.seq + 1)
    unwritten = run.assignments.not_written
    for first_no, offset, last_no, text in logical_lines(data, run, (b"#", b";")):
        stripped = text.strip()
        if not stripped or stripped[0] in "#;":
            continue
        if stripped.startswith("[") and stripped.endswith("]"):
            section = stripped[1:-1]
            continue
        key, sep, value = stripped.partition("=")
        if not sep:
            other += 1
            continue
        count += 1
        item = {"line": first_no, "last_line": last_no, "byte_offset": offset, **view_assignment(section, key.strip(), value.strip())}
        if item.get("resets_list"):
            resets += 1
        if item.get("exec"):
            execs += 1
        if len(shown) < MAX_SHOWN_ASSIGNMENTS:
            shown.append(item)
        else:
            run.assignments.add({"entry_id": first_entry_id, "file": path, **item})
        if run.text.enabled:
            run.text.add({"record_type": "assignment", "entry_id": first_entry_id, "file": path, "line": first_no, "last_line": last_no, "byte_offset": offset,
                          "section": section, "key": key.strip(), "value": value.strip()})
    name = os.path.basename(path)
    ext = next((s for s in UNIT_SUFFIXES if (dropin_of or name).endswith(s)), None)
    row = {"kind": "dropin" if dropin_of else "unit", "unit": (dropin_of if dropin_of else name), "unit_type": ext[1:] if ext else None, "manager": manager,
           "file": path, "file_modified": iso_mtime(path), "mode": mode_of(path), "bytes": len(data),
           "configuration": {"assignments": shown, "assignment_count": count, "assignments_shown": len(shown), "lines_without_assignment": other,
                             "list_resets": resets, "exec_lines": execs},
           "execution": "not_attempted", "effective_state": "unresolved"}
    if dropin_of:
        row["dropin_order"] = order
        row["dropin_note"] = "applied over the unit file in file-name order (the name of this file is %d bytes)" % blen(name)
    if count > len(shown):
        row["configuration"]["assignments_not_shown"] = count - len(shown)
        row["configuration"]["assignments_not_shown_where"] = "pages.assignments (entry_id %s), and the file at the lines given" % first_entry_id
    if run.assignments.not_written > unwritten:
        row["configuration"]["assignments_not_paged"] = run.assignments.not_written - unwritten
    if run.home:
        row["home"], row["account_in_passwd"] = run.home
    saved = run.entry(row)
    if not dropin_of:
        run.unit_names.setdefault((manager, name), []).append(saved["id"])


def desktop_entry(run, path, kind):
    run.check()
    data, why = read_regular(path, MAX_UNIT_BYTES)
    if data is None:
        run.error(path, why)
        return
    shown, count, section, exec_len = [], 0, None, None
    for first_no, offset, last_no, text in logical_lines(data, run, (b"#",)):
        stripped = text.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.startswith("[") and stripped.endswith("]"):
            section = stripped[1:-1]
            continue
        key, sep, value = stripped.partition("=")
        if not sep:
            continue
        count += 1
        key, value = key.strip(), value.strip()
        if key == "Exec":
            exec_len = {"words": len(value.split()), "bytes": blen(value), "line": first_no, "byte_offset": offset}
        elif key in DESKTOP_SHOWN and DESKTOP_SHOWN[key].fullmatch(value) and len(shown) < MAX_SHOWN_ASSIGNMENTS:
            shown.append({"key": key, "value": value, "line": first_no, "byte_offset": offset})
        if run.text.enabled:
            run.text.add({"record_type": "desktop", "file": path, "line": first_no, "byte_offset": offset, "section": section, "key": key, "value": value})
    run.entry({"kind": kind, "file": path, "file_modified": iso_mtime(path), "mode": mode_of(path), "bytes": len(data),
               "configuration": {"exec": exec_len, "shown": shown, "assignment_count": count}, "execution": "not_attempted", "effective_state": "unresolved"})


def script_entry(run, path, kind):
    """rc.local and init.d scripts: listed with their size, mode (executable bit), first line's shape and line count; the text is in the evidence."""
    run.check()
    data, why = read_regular(path, MAX_UNIT_BYTES)
    if data is None:
        run.error(path, why)
        return
    first = data.split(b"\n", 1)[0].rstrip(b"\r")
    shebang = first.startswith(b"#!")
    run.entry({"kind": kind, "file": path, "file_modified": iso_mtime(path), "mode": mode_of(path), "bytes": len(data), "lines": data.count(b"\n") + (0 if data.endswith(b"\n") or not data else 1),
               "executable": bool(os.lstat(path).st_mode & 0o111), "first_line": {"is_shebang": shebang, "bytes": len(first)},
               "configuration": "the script's text is in the evidence at this file (and in the text file when write_text was asked); it is not parsed",
               "execution": "not_attempted", "effective_state": "unresolved"})
    if run.text.enabled:
        run.text.add({"record_type": kind, "file": path, "text": decode(data)})


def cron_file(run, path, has_user, owner):
    run.check()
    data, why = read_regular(path, MAX_UNIT_BYTES)
    if data is None:
        run.error(path, why)
        return
    start = 0
    number = 0
    entries = 0
    size = len(data)
    while start <= size:
        number += 1
        if (number & 4095) == 0:
            run.check()
        end = data.find(b"\n", start)
        if end < 0:
            end = size
        raw = data[start:end]
        offset = start
        start = end + 1
        line = decode(raw.rstrip(b"\r"))
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            if start > size:
                break
            continue
        if run.text.enabled:
            run.text.add({"record_type": "cron", "file": path, "line": number, "byte_offset": offset, "text": line})
        if CRON_ASSIGN.match(stripped):
            run.entry({"kind": "cron_environment", "file": path, "line": number, "byte_offset": offset, "bytes": blen(stripped), "value_withheld": True})
            if start > size:
                break
            continue
        words = stripped.split(None, 6 if has_user else 5)
        want = 7 if has_user else 6
        schedule = None
        if words and words[0].startswith("@"):
            fields_ok = len(words) >= (3 if has_user else 2) and CRON_FIELD.fullmatch(words[0])
            sched_n = 1
        else:
            fields_ok = len(words) >= want and all(CRON_FIELD.fullmatch(w) for w in words[:5])
            sched_n = 5
        if not fields_ok:
            run.unparsed.append({"file": path, "line": number, "byte_offset": offset, "reason": "matches no cron table line shape"})
        else:
            schedule = " ".join(words[:sched_n])
            user = words[sched_n] if has_user else owner
            command = " ".join(words[sched_n + (1 if has_user else 0):])
            entries += 1
            run.entry({"kind": "cron", "file": path, "line": number, "byte_offset": offset, "file_modified": iso_mtime(path), "mode": mode_of(path),
                       "configuration": {"schedule": schedule, "user": user if (user == "root" or user in run.known_users or (user and CRON_USER.fullmatch(user))) else None,
                                         "user_bytes": blen(user) if user else None, "command_bytes": blen(command), "command_words": len(command.split())},
                       "execution": "not_attempted", "effective_state": "unresolved"})
        if start > size:
            break


def scan_location(run, rel, handle, expect="dir"):
    """Visit one place, recording what it is (missing, a link not followed, an alias of a directory already read, read). `handle(run, path, rel_dir)` is
    given each regular file; links and sub-directories are handled here."""
    run.check()
    full = os.path.join(run.root, rel)
    try:
        if not os.path.lexists(full):
            run.census(rel, "missing")
            return
        if os.path.islink(full) or not inside(run.root, full):
            run.skipped_links.append({"file": full, "link_kind": "location"})
            run.census(rel, "link or outside the root: not followed", target_bytes=blen(os.readlink(full)) if os.path.islink(full) else None)
            return
        if expect == "dir" and not os.path.isdir(full):
            run.census(rel, "not a directory")
            return
        if expect == "file" and not os.path.isfile(full):
            run.census(rel, "not a regular file")
            return
        real = os.path.realpath(full)
    except OSError as exc:
        run.walk_errors.append({"path": full, "error": describe(exc)})
        run.census(rel, "error: %s" % describe(exc))
        return
    if real in run.seen_real:
        run.census(rel, "alias of %s (the same place reached through a link in its path): read once, there" % run.seen_real[real])
        return
    run.seen_real[real] = rel
    before = run.seq
    try:
        if expect == "file":
            handle(run, full, 0)
        else:
            walk_dir(run, full, handle, 0)
    except Overtime:
        run.census(rel, "stopped: the inventory ended inside this place (see partial_reason)", entries=run.seq - before)
        raise
    run.census(rel, "read", entries=run.seq - before)


def walk_dir(run, directory, handle, depth):
    try:
        names = walk_names(run, directory)
    except OSError as exc:
        run.walk_errors.append({"path": directory, "error": describe(exc)})
        return
    for position, name in enumerate(names):
        run.check()
        path = os.path.join(directory, name)
        try:
            info = os.lstat(path)
        except OSError as exc:
            run.error(path, describe(exc))
            continue
        if stat.S_ISLNK(info.st_mode):
            link_row(run, path, directory, None)
        elif stat.S_ISDIR(info.st_mode):
            if depth < MAX_DEPTH:
                walk_dir(run, path, handle, depth + 1)
            else:
                run.walk_errors.append({"path": path, "error": "deeper than %d directories: not read" % MAX_DEPTH})
        elif stat.S_ISREG(info.st_mode):
            handle(run, path, position)
        else:
            run.special.append({"file": path, "reason": "not a regular file (a pipe, a socket or a device): never opened"})


def unit_handler(manager):
    def handle(run, path, position):
        directory = os.path.basename(os.path.dirname(path))
        name = os.path.basename(path)
        if name.endswith(UNIT_SUFFIXES):
            unit_entry(run, path, manager)
        elif name.endswith(".conf") and directory.endswith(".d"):
            unit_entry(run, path, manager, dropin_of=directory[:-2], order=position)
    return handle


def cron_handler(has_user, from_user_dir):
    def handle(run, path, position):
        owner = os.path.basename(path) if from_user_dir else None
        cron_file(run, path, has_user, owner)
    return handle


def script_handler(kind):
    def handle(run, path, position):
        script_entry(run, path, kind)
    return handle


def desktop_handler(kind):
    def handle(run, path, position):
        if path.endswith(".desktop"):
            desktop_entry(run, path, kind)
    return handle


def read_passwd(run):
    path = os.path.join(run.root, "etc", "passwd")
    try:
        usable = os.path.isfile(path) and not os.path.islink(path) and inside(run.root, path)
    except OSError:
        usable = False
    if not usable:
        return None
    data, why = read_regular(path, MAX_UNIT_BYTES)
    if data is None:
        run.error(path, why)
        return None
    run.passwd_read = True
    text = decode(data)
    for line in text.split("\n"):
        name = line.split(":", 1)[0]
        if name and not name.startswith("#") and len(name) <= 256:
            run.known_users.add(name)
    return text


def homes_of(run, passwd):
    homes, ignored = [], []
    from_passwd = 0
    if passwd is not None:
        for line in passwd.split("\n"):
            fields = line.split(":")
            if len(fields) >= 6 and fields[5].startswith("/") and fields[5] not in ("/", "/nonexistent"):
                parts = [p for p in fields[5].split("/") if p]
                if ".." in parts or "." in parts or "\x00" in fields[5]:
                    if len(ignored) < MAX_NAMED:
                        ignored.append(blen(fields[5]))
                    continue
                homes.append("/".join(parts))
        from_passwd = len(homes)
    home_dir = os.path.join(run.root, "home")
    try:
        if os.path.isdir(home_dir) and not os.path.islink(home_dir):
            homes += ["home/" + n for n in walk_names(run, home_dir)]
    except OSError as exc:
        run.error(home_dir, describe(exc))
    homes.append("root")
    seen, unique = set(), []
    for h in homes:
        if h and h not in seen:
            seen.add(h)
            unique.append(h)
    listed = {h for h in homes[:from_passwd]}
    return unique, listed


def read_execution(paths, deadline):
    """Counts per unit from the rows the caller declared: {unit: [rows, first time, last time]}, and what was read."""
    units, info = {}, []
    for path in paths:
        row = {"file": path, "rows": 0, "rows_naming_a_unit": 0, "read": False}
        info.append(row)
        try:
            fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | getattr(os, "O_NOFOLLOW", 0))
        except OSError as exc:
            row["error"] = describe(exc)
            continue
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                row["error"] = "not a regular file"
                continue
            read = 0
            with os.fdopen(os.dup(fd), "rb") as fh:
                for number, raw in enumerate(fh):
                    read += len(raw)
                    if (number & 1023) == 0 and time.monotonic() > deadline:
                        row["error"] = "max_seconds passed while this file was read"
                        break
                    if read > MAX_EXECUTION_BYTES or row["rows"] >= MAX_EXECUTION_ROWS:
                        row["error"] = "more than %d bytes or %d rows: the rest was not read" % (MAX_EXECUTION_BYTES, MAX_EXECUTION_ROWS)
                        break
                    row["rows"] += 1
                    try:
                        entry = json.loads(raw)
                    except (ValueError, RecursionError):
                        row["rows_not_json"] = row.get("rows_not_json", 0) + 1
                        continue
                    if not isinstance(entry, dict):
                        continue
                    for field, scope in (("unit", "system"), ("user_unit", "user")):
                        name = entry.get(field)
                        if isinstance(name, str) and 0 < len(name) <= 256:
                            row["rows_naming_a_unit"] += 1
                            stamp = entry.get("time") if isinstance(entry.get("time"), str) else None
                            key = (scope, name)
                            if key in units or len(units) < MAX_EXECUTION_UNITS:
                                slot = units.setdefault(key, [0, stamp, stamp])
                                slot[0] += 1
                                if stamp is not None:
                                    slot[1] = stamp if slot[1] is None or stamp < slot[1] else slot[1]
                                    slot[2] = stamp if slot[2] is None or stamp > slot[2] else slot[2]
                            else:
                                row["units_not_counted"] = row.get("units_not_counted", 0) + 1
            row["read"] = "error" not in row
        except OSError as exc:
            row["error"] = describe(exc)
        finally:
            os.close(fd)
    return units, info


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


def main():
    args = read_args()
    root = want_str(args, "root", "root is required: the directory of an extracted Linux root (etc/, var/, usr/, home/ ...)")
    execution_paths = want_paths_list(args, "execution_rows")
    limit = want_limit(args)
    write_text = want_flag(args, "write_text")
    seconds = want_seconds(args, "max_seconds", DEFAULT_SECONDS, MAX_SECONDS)
    try:
        if os.path.islink(root) or not os.path.isdir(root):
            if not os.path.exists(root):
                fail("no such directory", root=root)
            fail("root must be a directory of the evidence and not a link, a file or a device", root=root)
    except (OSError, ValueError) as exc:
        fail("the root cannot be read: %s" % describe(exc), root=root)
    refuse_disk_image(root, "root")
    for item in execution_paths:
        refuse_disk_image(item, "execution_rows")
    try:
        text = TextFile(TEXT_NAME, write_text, "JSON Lines, mode 0600: every assignment, cron line and desktop entry whole, and the text of rc.local and init.d scripts, with file, line and byte offset", flag="write_text")
    except TextRefused as exc:
        fail(str(exc))
    STATE["text"] = text
    entries = LosslessPage(TOOL, "entries", limit)
    assignments = LosslessPage(TOOL, "assignments", INLINE_LIST)
    started = time.monotonic()
    deadline = started + seconds
    run = Run(root, text, entries, assignments, deadline, seconds)
    stopped = None
    homes, homes_basis, home_unlisted = [], "", 0
    try:
        passwd = read_passwd(run)
        homes, in_passwd = homes_of(run, passwd)
        for rel in CRON_FILES:
            scan_location(run, rel, lambda r, p, i: cron_file(r, p, True, None), expect="file")
        for rel in CRON_DIRS:
            user_dir = rel.startswith("var/spool/cron")
            scan_location(run, rel, cron_handler(not user_dir, user_dir))
        for rel in SYSTEM_UNIT_DIRS:
            scan_location(run, rel, unit_handler("system"))
        for rel in GLOBAL_USER_UNIT_DIRS:
            scan_location(run, rel, unit_handler("user"))
        scan_location(run, "etc/rc.local", script_handler("rc_local"), expect="file")
        scan_location(run, "etc/init.d", script_handler("init_script"))
        scan_location(run, "etc/xdg/autostart", desktop_handler("autostart"))
        for home in homes:
            run.check()
            run.home = (home, home in in_passwd)
            for sub in HOME_UNIT_DIRS:
                scan_location(run, "%s/%s" % (home, sub), unit_handler("user"))
            scan_location(run, "%s/.config/autostart" % home, desktop_handler("autostart"))
            run.home = None
    except Overtime:
        stopped = "max_seconds (%s) passed: the inventory stopped there and the places after it were not looked in" % seconds
    text.close()
    units, execution_files = ({}, [])
    if execution_paths and stopped is None:
        try:
            units, execution_files = read_execution(execution_paths, deadline)
        except OSError as exc:
            execution_files = [{"error": describe(exc)}]
    known = run.unit_names
    pages = {"entries": entries.finish(), "assignments": assignments.finish(), "locations": run.locations.finish()}
    listed = {}
    for key, items in (("read_errors", run.read_errors), ("walk_errors", run.walk_errors), ("links_not_followed", run.skipped_links),
                       ("not_regular", run.special), ("unparsed_lines", run.unparsed)):
        pages[key] = items.settle()
        listed[key] = {"total": items.page.total, "shown": list(items)}
    execution = {"status": "not_attempted", "why": "no execution_rows were declared: this tool lists configuration and does not look for evidence that a unit ran"}
    if execution_paths:
        counted = 0
        for (manager, name), ids in known.items():
            hit = units.get((manager, name))
            if hit:
                counted += 1
        execution = {"status": "read" if all(f.get("read") for f in execution_files) and stopped is None else "partial", "files": execution_files,
                     "units_named_in_rows": len(units), "listed_units_named": counted, "listed_units": len(known),
                     "per_unit": [{"unit": n, "scope": s, "rows": v[0], "first_time": v[1], "last_time": v[2]} for (s, n), v in sorted(units.items(), key=lambda kv: (-kv[1][0], kv[0]))[:INLINE_LIST]],
                     "per_unit_total": len(units),
                     "note": "rows that name a unit show that the journal recorded that unit; a unit these rows do not name is not shown to have been idle, and the rows are as complete as the journal that was read"}
    links = run.links_seen
    if links:
        link_note = "%d link(s) were found in the unit directories: masks, aliases and enablement are read from them (links_not_followed lists each, with its kind)" % links
    elif run.unit_files:
        link_note = ("no link was found in any unit directory although %d unit file(s) were: either nothing is enabled, masked or aliased, or this copy did not keep "
                     "links (a copy made with target-fs does not copy links as links). Enablement, masks and aliases cannot be read from it; read them from an image "
                     "route or a copy that keeps links" % run.unit_files)
    else:
        link_note = "no unit file and no link was found"
    problems = []
    if stopped:
        problems.append(stopped)
    if run.partial_reason:
        problems.append(run.partial_reason)
    errors = pages["read_errors"]["matched"] + pages["walk_errors"]["matched"]
    if errors:
        problems.append("%d file(s) or director(ies) could not be read (see read_errors, walk_errors)" % errors)
    if pages["unparsed_lines"]["matched"]:
        problems.append("%d cron line(s) match no table line shape (see unparsed_lines)" % pages["unparsed_lines"]["matched"])
    capped = capped_why(pages, text)
    if capped:
        problems.append(capped)
    if execution_paths and execution["status"] != "read":
        problems.append("the execution rows were not all read")
    outcome = status_of(not problems, False,
                        "every place named in locations was looked in and every file in it was read; effective_state is unresolved by design and execution is as the execution field says",
                        "; ".join(problems) or "partial", "")
    out = {"parser": PARSER, "root": root, **outcome, "entries_total": pages["entries"]["matched"], "by_kind": run.kinds,
           "locations_tried": pages["locations"]["matched"], "locations_by_state": run.by_state,
           "locations": {"shown": run.locations.page, "all": pages["locations"].get("all_results"), "note": "every place tried is in pages.locations"},
           "accounts": {"passwd_read": run.passwd_read, "homes_looked_for": len(homes),
                        "note": ("homes come from etc/passwd of the root and from the directories under home/ and root: an entry with account_in_passwd false is in a home "
                                 "the passwd does not list (a deleted account)") if run.passwd_read else
                                "etc/passwd was not found in the root: homes come from the directories under home/ and root only, and no account is known"},
           "links": {"found": links, "note": link_note},
           "effective_state": {"status": "unresolved", "why": EFFECTIVE_WHY},
           "execution": execution, **listed, "text": text.summary(), "entries": entries.page, "pages": pages, "truncated": pages["entries"]["truncated"],
           "note": "configuration and execution are separate: an entry says what a file configures and never that it ran. Command lines and environments are lengths, "
                   "and a key name systemd does not define is a length; the text is in the evidence at the file, line and byte offset each entry gives."}
    if stopped:
        out["stopped_because"] = stopped
    hold_stop_signals()
    STATE["answering"] = True
    print(json.dumps(out, indent=2))


def last_resort(exc):
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
            hold_stop_signals()
            last_resort(exc)
    except SystemExit as stop:
        exit_code = _code(stop)
    _leave(exit_code)
