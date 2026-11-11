#!/usr/bin/env python3
"""Give the effective view of a container's layers from the layer directories alone: which layer supplies each path and what each layer did to it.

Nothing is started and nothing is mounted. The layers are directories the caller names (extracted layer trees, or overlay2's own
`<id>/diff`), and the view is built the way a union file system builds it: from the top layer down, a path is supplied by the topmost
layer that has it, unless a higher layer deleted it (a whiteout) or made the directory above it opaque.

  OCI whiteouts    a file named `.wh.<name>` deletes `<name>` of the same directory in the layers below; `.wh..wh..opq` in a directory makes
                   it opaque (the layers below contribute nothing under it). These are ordinary files and survive any extraction.
  overlayfs native a character device with device number 0/0 is a whiteout; the xattr `trusted.overlay.opaque` (`user.overlay.opaque` for a
                   rootless mount) set to `y` on a directory makes it opaque. An extraction that does not carry extended attributes (tar
                   without --xattrs, a copy made by an unprivileged user, a file system without them) loses the opaque marker, and one that
                   cannot make device nodes loses the whiteout: the answer says, for each layer, whether the attribute could be read here
                   and what was found, and an opaque directory of a layer whose attributes were not readable is not told from an ordinary one.

The layers come in one of two ways: `layers`, a list of directories from the base layer to the top (with an optional `upper`, the
container's writable layer); or `overlay2_root` and `start`: overlay2's own storage, where `start` is the name of a layer directory
(a container's mount id, or an image layer's cache id) whose `lower` file lists its lower layers as `l/<short id>` links that are
resolved inside `overlay2_root` and nowhere else. A lower layer that cannot be resolved is `missing` and named; a chain cut by one is partial.
A link in a layer is listed as a link and never followed; a layer deeper than 4,096 or a chain that repeats a layer is refused.

The tool lists and counts; it copies a file only when `copy_paths` names it, to $OUT/layers-view/ in a job run as secret output, never
over a file that is there (a name taken is not replaced). It does not read a file's content otherwise, so a secret in a file is not seen.
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

TOOL = "container_layers"
PARSER = "container_layers/2"


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
MAX_LAYERS = 4096
MAX_LAYER_ENTRIES = 200000    # entries of one layer that are read
MAX_TOTAL_PATHS = 500000      # distinct paths followed in all
MAX_DEPTH = 512               # path components
MAX_COPY_FILES = 1000
MAX_COPY_BYTES = 512 << 20
MAX_COPY_FILE = 64 << 20
CLOCK_ENTRIES = 256

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

ID64 = re.compile(r"[0-9a-f]{64}")
SHORT = re.compile(r"l/[A-Z0-9]{10,60}")
OPAQUE_XATTRS = ("trusted.overlay.opaque", "user.overlay.opaque")
WH = ".wh."
WH_OPAQUE = ".wh..wh..opq"


class Overtime(Exception):
    pass


def want_dir_list(args, key, most):
    value = args.get(key)
    if value is None:
        return None
    if not isinstance(value, list) or not value or len(value) > most or not all(isinstance(x, str) and x and len(x) <= 4096 and "\x00" not in x for x in value):
        fail("%s must be a list of 1 to %d directory names" % (key, most))
    for item in value:
        try:
            os.fsencode(item)
        except (UnicodeEncodeError, ValueError):
            fail("%s holds a name a file cannot have (a lone surrogate)" % key)
    return value


def want_relative_list(args, key, most):
    value = want_dir_list(args, key, most) if args.get(key) is not None else None
    if value is None:
        return None
    out = []
    for item in value:
        parts = [p for p in item.split("/") if p not in ("", ".")]
        if item.startswith("/") or ".." in parts or not parts or len(parts) > MAX_DEPTH:
            fail("%s holds a path that is not a plain path inside the layers (no leading /, no ..): %d bytes" % (key, blen(item)))
        out.append("/".join(parts))
    return out


def iso(ts):
    try:
        return datetime.datetime.fromtimestamp(ts, datetime.timezone.utc).isoformat().replace("+00:00", "Z")
    except (OverflowError, OSError, ValueError):
        return None


def real_dir(path):
    """The directory as given if it is a real directory (not a link, not a file)."""
    try:
        info = os.lstat(path)
    except OSError as exc:
        return None, describe(exc)
    if stat.S_ISLNK(info.st_mode):
        return None, "a link is not followed: name the directory it points to"
    if not stat.S_ISDIR(info.st_mode):
        return None, "not a directory"
    return path, None


def read_head(path, limit):
    """Up to `limit` bytes of a regular file: opened without waiting and without following a link, and looked at with fstat first, so a FIFO,
    a device or a directory at this name is an OSError and never holds the tool."""
    fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0))
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise OSError("not a regular file (a pipe, a socket or a device is never read)")
        chunks, left = [], limit
        while left > 0:
            part = os.read(fd, min(left, 1 << 20))
            if not part:
                break
            chunks.append(part)
            left -= len(part)
        return b"".join(chunks)
    finally:
        os.close(fd)


def resolve_chain(overlay_root, start, notes):
    """The layer directories of overlay2's `start`, top to base, as [(name, diff dir)] and the short ids that could not be resolved.
    Each `lower` entry is `l/<short>`, a link in overlay_root/l to ../<id>/diff, resolved here and accepted only inside overlay_root."""
    chain, missing, seen = [], [], set()
    if start in (".", "..") or "/" in start or "\x00" in start:
        return None, [], "the start layer must be the name of a directory inside overlay2_root (no path, no . or ..)"
    top = os.path.join(overlay_root, start)
    ok, why = real_dir(top)
    if ok is None:
        return None, [], "the start layer %s: %s" % (start if re.fullmatch(r"[A-Za-z0-9_.\-]{1,100}", start) else "(name withheld)", why)
    diff = os.path.join(top, "diff")
    ok, why = real_dir(diff)
    chain.append((start, diff if ok else None))
    seen.add(start)
    if ok is None:
        missing.append({"layer": start, "why": "no diff directory (%s)" % why})
    lower_file = os.path.join(top, "lower")
    try:
        raw = read_head(lower_file, 1 << 20).decode("utf-8", "replace").strip()
    except FileNotFoundError:
        notes.append("%s has no lower file: it is a base layer" % start)
        return chain, missing, None
    except OSError as exc:
        return chain, missing, "the lower file could not be read: %s" % describe(exc)
    for short in raw.split(":")[:MAX_LAYERS + 1]:
        if len(chain) > MAX_LAYERS:
            return chain, missing, "the chain is longer than %d layers: not followed further" % MAX_LAYERS
        if not SHORT.fullmatch(short):
            missing.append({"layer": None, "why": "a lower entry (%d bytes) is not an overlay2 short id l/<id>: another layout" % blen(short)})
            continue
        link = os.path.join(overlay_root, short)
        try:
            target = os.readlink(link)
        except OSError as exc:
            missing.append({"layer": short, "why": "the link %s is not there (%s)" % (short, describe(exc))})
            continue
        m = re.fullmatch(r"\.\./([A-Za-z0-9_.\-]{1,100})/diff", target)
        if not m:
            missing.append({"layer": short, "why": "the link does not point at ../<id>/diff"})
            continue
        name = m.group(1)
        if name in (".", ".."):
            missing.append({"layer": short, "why": "the link names a directory outside the store (. or ..), which is never followed"})
            continue
        if name in seen:
            return chain, missing, "the chain repeats the layer %s: a loop, not followed further" % name
        seen.add(name)
        diff = os.path.join(overlay_root, name, "diff")
        ok, why = real_dir(diff)
        if ok is None:
            missing.append({"layer": name, "short_id": short, "why": "its diff directory: %s" % why})
            chain.append((name, None))
        else:
            chain.append((name, diff))
    return chain, missing, None


def xattr_status(directory):
    """Whether the extended attributes of this layer can be read here: a probe of its root directory."""
    try:
        os.listxattr(directory, follow_symlinks=False)
        return "readable"
    except AttributeError:
        return "not readable here (this platform has no extended attribute calls)"
    except OSError as exc:
        return "not readable here (%s)" % describe(exc)


def walk_layer(directory, run, index, stats):
    """Every entry of one layer, depth first without recursion and without following a link: [(path, kind, info)] with path relative to the layer.
    kind: dir, file, symlink, native_whiteout, oci_whiteout, oci_opaque, other. Bounded by MAX_LAYER_ENTRIES, MAX_DEPTH and the clock."""
    out = []
    stack = [("", 0)]
    count = 0
    while stack:
        rel, depth = stack.pop()
        base = os.path.join(directory, rel) if rel else directory
        try:
            with os.scandir(base) as it:
                children = sorted(it, key=lambda e: e.name)
        except OSError as exc:
            stats["errors"].append({"layer": index, "path_bytes": blen(rel), "error": describe(exc)})
            continue
        for entry in children:
            count += 1
            if (count % CLOCK_ENTRIES) == 0:
                run.check()
            if count > MAX_LAYER_ENTRIES:
                stats["capped"] = True
                return out
            name = entry.name
            path = rel + "/" + name if rel else name
            try:
                info = entry.stat(follow_symlinks=False)
            except OSError as exc:
                stats["errors"].append({"layer": index, "path_bytes": blen(path), "error": describe(exc)})
                continue
            mode = info.st_mode
            if name == WH_OPAQUE:
                kind = "oci_opaque"
            elif name.startswith(WH) and not name.startswith(WH + WH):
                kind = "oci_whiteout"
            elif stat.S_ISCHR(mode) and info.st_rdev == 0:
                kind = "native_whiteout"
            elif stat.S_ISDIR(mode):
                kind = "dir"
            elif stat.S_ISREG(mode):
                kind = "file"
            elif stat.S_ISLNK(mode):
                kind = "symlink"
            else:
                kind = "other"
            out.append((path, kind, info))
            if kind == "dir":
                if depth + 1 < MAX_DEPTH:
                    stack.append((path, depth + 1))
                else:
                    stats["deep"] = stats.get("deep", 0) + 1
    return out


def is_opaque_dir(directory, path, stats):
    for attr in OPAQUE_XATTRS:
        try:
            value = os.getxattr(os.path.join(directory, path), attr, follow_symlinks=False)
            stats["xattr_read"] += 1
            if value[:1] == b"y":
                return True
        except OSError:
            pass
        except AttributeError:
            return False
    return False


def hidden_by(path, whiteouts, opaque, blockers):
    """The (layer index, kind) that hides `path` for a layer below the one that set them, or None. A whiteout hides the path and everything under it;
    an opaque directory hides what is below it, not itself."""
    cur = path
    while cur:
        if cur in whiteouts:
            return whiteouts[cur], "whiteout"
        cur = cur.rpartition("/")[0]
        if cur and cur in opaque:
            return opaque[cur], "opaque"
        if cur and cur in blockers:
            return blockers[cur], "non_directory"
    return None


class Run:
    def __init__(self, deadline):
        self.deadline = deadline

    def check(self):
        if time.monotonic() > self.deadline:
            raise Overtime()


def effective_view(layers, run, stats):
    """layers: [(label, dir or None)] from the TOP down. Returns {path: record}, built top to bottom."""
    paths = {}
    whiteouts, opaque, blockers = {}, {}, {}    # path -> top-down index of the layer that set it (a blocker: a file or link where a lower layer holds a directory)
    for index, (label, directory) in enumerate(layers):
        if directory is None:
            continue
        info = {"entries": 0, "files": 0, "dirs": 0, "symlinks": 0, "oci_whiteouts": 0, "oci_opaque_dirs": 0, "native_whiteouts": 0, "native_opaque_dirs": 0,
                "other": 0, "xattr_read": 0, "xattrs": xattr_status(directory), "capped": False, "errors": []}
        stats["layer_info"][index] = info
        try:
            entries = walk_layer(directory, run, index, info)
        except Overtime:
            info["capped"] = True
            raise
        info["entries"] = len(entries)
        new_whiteouts, new_opaque, new_blockers = {}, {}, {}
        for path, kind, st in entries:
            if kind == "oci_whiteout":
                info["oci_whiteouts"] += 1
                parent, _, name = path.rpartition("/")
                target = (parent + "/" if parent else "") + name[len(WH):]
                new_whiteouts.setdefault(target, index)
                continue
            if kind == "oci_opaque":
                info["oci_opaque_dirs"] += 1
                new_opaque.setdefault(path.rpartition("/")[0], index)
                continue
            if kind == "native_whiteout":
                info["native_whiteouts"] += 1
                new_whiteouts.setdefault(path, index)
                continue
            if kind == "dir":
                info["dirs"] += 1
                if is_opaque_dir(directory, path, info):
                    info["native_opaque_dirs"] += 1
                    new_opaque.setdefault(path, index)
            elif kind == "file":
                info["files"] += 1
            elif kind == "symlink":
                info["symlinks"] += 1
            else:
                info["other"] += 1
            if kind != "dir":
                new_blockers.setdefault(path, index)
            record = paths.get(path)
            if record is None:
                if len(paths) >= MAX_TOTAL_PATHS:
                    stats["paths_not_followed"] += 1
                    continue
                record = paths[path] = {"mentions": [], "supplier": None}
            hid = hidden_by(path, whiteouts, opaque, blockers)
            if hid is not None:
                record["mentions"].append((index, "hidden_by_" + hid[1], kind, hid[0]))
            elif record["supplier"] is not None:
                record["mentions"].append((index, "shadowed", kind, None))
            else:
                record["supplier"] = (index, kind, st)
                record["mentions"].append((index, "supplies", kind, None))
        for target, i in new_whiteouts.items():
            record = paths.get(target)
            if record is None and len(paths) < MAX_TOTAL_PATHS:
                record = paths[target] = {"mentions": [], "supplier": None}
            if record is not None:
                record["mentions"].append((index, "deletes", "whiteout", None))
        for target, i in new_whiteouts.items():
            whiteouts.setdefault(target, index)
        for target, i in new_blockers.items():
            blockers.setdefault(target, index)
        for target, i in new_opaque.items():
            opaque.setdefault(target, index)
            record = paths.get(target)
            if record is not None:
                record["mentions"].append((index, "makes_opaque", "dir", None))
        # a whiteout also names the path it hides when the layers below have it: handled when they are read (hidden_by)
    return paths


def build_rows(paths, layers_top_down, prefix, run=None):
    """Rows of the effective view, ordered by path. Layer numbers in the rows count from the BASE (0) up; the writable layer, when given, is the highest."""
    n = len(layers_top_down)

    def base_index(i):
        return n - 1 - i

    rows = []
    for number, path in enumerate(sorted(paths)):
        if run is not None and (number & 255) == 0:
            run.check()
        if prefix and not (path == prefix or path.startswith(prefix + "/")):
            continue
        record = paths[path]
        mentions = sorted(record["mentions"], key=lambda m: -m[0])        # from the base up
        changes = []
        first = True
        below_kind = None
        for index, action, kind, by in mentions:
            layer = base_index(index)
            if action in ("supplies", "shadowed") or action.startswith("hidden_by"):
                if action in ("hidden_by_opaque", "hidden_by_non_directory"):
                    what = "hidden: its own layer's entry is hidden by a %s in layer %d" % (action[len("hidden_by_"):], base_index(by))
                    changes.append({"layer": layer, "action": "present_but_hidden", "why": what})
                else:
                    # a whiteout above names itself in its own layer ("deleted"); an opaque directory is the only thing that hides without saying so at the path
                    verb = "added" if first else ("merged" if kind == "dir" and below_kind == "dir" else "replaced")
                    changes.append({"layer": layer, "action": verb, "type": kind})
                    below_kind = kind
                first = False
            elif action == "deletes":
                changes.append({"layer": layer, "action": "deleted"})
                first = True
                below_kind = None
            elif action == "makes_opaque":
                changes.append({"layer": layer, "action": "made_opaque"})
        row = {"path": path, "visible": record["supplier"] is not None}
        if record["supplier"] is not None:
            index, kind, st = record["supplier"]
            row.update({"supplied_by": base_index(index), "type": kind, "size": st.st_size if kind == "file" else None, "mode": "%04o" % (st.st_mode & 0o7777),
                        "modified": iso(st.st_mtime)})
        else:
            deleters = [m[0] for m in mentions if m[1] == "deletes"]
            row["why_not_visible"] = "deleted by layer %d" % base_index(min(deleters)) if deleters else "hidden"
        row["changes"] = changes
        rows.append(row)
    return rows


def materialise(requested, paths, layers_top_down, out_dir, run, stats):
    """Copy the named effective files to out_dir/<path>, never over a file that is there. Returns one row per request."""
    results, copied_bytes = [], 0
    for request in requested:
        run.check()
        row = {"path": request}
        record = paths.get(request)
        if record is None or record["supplier"] is None:
            row["copied"] = False
            row["why"] = "not in the effective view" if record is None else "deleted or hidden: no layer supplies it"
        elif record["supplier"][1] != "file":
            row["copied"] = False
            row["why"] = "supplied as %s: only regular files are copied" % record["supplier"][1]
        elif len(results) >= MAX_COPY_FILES:
            row["copied"] = False
            row["why"] = "more than %d files asked for" % MAX_COPY_FILES
        else:
            index, kind, st = record["supplier"]
            source_dir = layers_top_down[index][1]
            source = os.path.join(source_dir, request)
            row["supplied_by"] = len(layers_top_down) - 1 - index
            try:
                real_parent = os.path.realpath(os.path.dirname(source))
                if os.path.commonpath((real_parent, os.path.realpath(source_dir))) != os.path.realpath(source_dir):
                    raise OSError("a link in the path leaves the layer")
                fd = os.open(source, os.O_RDONLY | os.O_NONBLOCK | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0))
            except (OSError, ValueError) as exc:
                row.update({"copied": False, "why": "the source could not be opened: %s" % describe(exc)})
                results.append(row)
                continue
            tmp = None
            try:
                info = os.fstat(fd)
                if not stat.S_ISREG(info.st_mode):
                    row.update({"copied": False, "why": "not a regular file"})
                elif info.st_size > MAX_COPY_FILE or copied_bytes + info.st_size > MAX_COPY_BYTES:
                    row.update({"copied": False, "why": "over the copy bounds (%d bytes a file, %d in all)" % (MAX_COPY_FILE, MAX_COPY_BYTES)})
                else:
                    target = Path(out_dir) / request
                    target.parent.mkdir(parents=True, exist_ok=True)
                    tmp = str(target.parent / (".%s.%s" % (target.name[:60], secrets.token_hex(6))))
                    wfd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
                    size = 0
                    with os.fdopen(wfd, "wb") as out:
                        while True:
                            run.check()
                            block = os.read(fd, 1 << 20)
                            if not block:
                                break
                            size += len(block)
                            if size > MAX_COPY_FILE:
                                raise OSError("the file grew past the copy bound while it was read")
                            out.write(block)
                        out.flush()
                        os.fsync(out.fileno())
                    placed = place_without_replacing(tmp, target)
                    tmp = None
                    copied_bytes += size
                    row.update({"copied": True, "bytes": size, "placed_as": str(placed).replace(out_dir.rstrip("/"), "$OUT/layers-view", 1)})
            except OSError as exc:
                row.update({"copied": False, "why": "the copy failed: %s" % describe(exc)})
            finally:
                os.close(fd)
                if tmp is not None:
                    try:
                        os.unlink(tmp)
                    except OSError:
                        pass
        results.append(row)
    return results


def main():
    args = read_args()
    layer_dirs = want_dir_list(args, "layers", MAX_LAYERS)
    overlay_root = want_str(args, "overlay2_root")
    start = want_str(args, "start")
    upper = want_str(args, "upper")
    prefix_raw = want_str(args, "path_prefix")
    copy_paths = want_relative_list(args, "copy_paths", MAX_COPY_FILES)
    copy = want_flag(args, "copy")
    if bool(copy_paths) != copy:
        fail("copy and copy_paths go together: copy: true with the effective files to copy in copy_paths (the flag is what makes the job a secret-output job)")
    limit = want_limit(args)
    seconds = want_seconds(args, "max_seconds", DEFAULT_SECONDS, MAX_SECONDS)
    if (layer_dirs is None) == (overlay_root is None):
        fail("name the layers one way: layers (a list of directories from the base to the top, with an optional upper) or overlay2_root with start")
    if overlay_root is not None and (start is None or layer_dirs is not None or upper is not None):
        fail("overlay2_root takes start, and neither layers nor upper")
    if overlay_root is None and start is not None:
        fail("start belongs to overlay2_root")
    prefix = None
    if prefix_raw is not None:
        parts = [p for p in prefix_raw.split("/") if p not in ("", ".")]
        if prefix_raw.startswith("/") or ".." in parts:
            fail("path_prefix must be a plain path inside the layers (no leading /, no ..)")
        prefix = "/".join(parts)
    if copy_paths:
        require_job("copy_paths")
    started = time.monotonic()
    deadline = started + seconds
    run = Run(deadline)
    stats = {"layer_info": {}, "paths_not_followed": 0, "xread": {"xattr_read": 0}, "errors": []}
    notes, missing, chain_problem = [], [], None
    top_down = []
    if layer_dirs is not None:
        for item in layer_dirs + ([upper] if upper else []):
            ok, why = real_dir(item)
            if ok is None:
                fail("a layer directory cannot be used: %s" % why, layer_bytes=blen(item))
        top_down = ([("upper", upper)] if upper else []) + [(d, d) for d in reversed(layer_dirs)]
        top_down = [(label, directory) for label, directory in top_down]
    else:
        ok, why = real_dir(overlay_root)
        if ok is None:
            fail("overlay2_root cannot be used: %s" % why)
        chain, missing, chain_problem = resolve_chain(overlay_root, start, notes)
        if chain is None:
            fail(chain_problem)
        top_down = chain
    n = len(top_down)
    output = os.environ.get("OUT")
    page = LosslessPage(TOOL, "view", limit)
    STATE["text"] = None
    stopped = None
    paths = {}
    try:
        paths = effective_view(top_down, run, stats)
    except Overtime:
        stopped = "max_seconds (%s) passed: the layers below the one being read were not read" % seconds
    rows = []
    if stopped is None:
        try:
            rows = build_rows(paths, top_down, prefix, run)
            for number, row in enumerate(rows):
                if (number & 255) == 0:
                    run.check()
                page.add(row)
        except Overtime:
            stopped = "max_seconds (%s) passed while the view was being listed: the rows after the last one written are not in it" % seconds
    materialised = None
    if copy_paths and stopped is None:
        out_dir = os.path.join(output, "layers-view")
        try:
            materialised = materialise(copy_paths, paths, top_down, out_dir, run, stats)
        except Overtime:
            stopped = "max_seconds (%s) passed while files were being copied" % seconds
    layers_report = []
    for index in range(n - 1, -1, -1):
        label, directory = top_down[index]
        info = stats["layer_info"].get(index)
        item = {"layer": n - 1 - index, "label": label if (overlay_root is not None or label == "upper") else None, "directory": directory if layer_dirs is not None else None,
                "role": "writable (upper)" if (index == 0 and (upper or overlay_root)) else "lower"}
        if directory is None:
            item["state"] = "missing"
        elif info is None:
            item["state"] = "not read"
        else:
            item.update({"state": "read", **{k: v for k, v in info.items() if k != "errors"}, "read_errors": len(info["errors"])})
        layers_report.append(item)
    problems = []
    if stopped:
        problems.append(stopped)
    if missing or chain_problem:
        problems.append("%d layer(s) of the chain could not be resolved%s" % (len(missing), "; " + chain_problem if chain_problem else ""))
    if stats["paths_not_followed"]:
        problems.append("%d path(s) past the %d this tool follows were not followed" % (stats["paths_not_followed"], MAX_TOTAL_PATHS))
    capped = [i for i, v in stats["layer_info"].items() if v["capped"]]
    if capped:
        problems.append("layer(s) %s hold more than %d entries: the rest of each was not read" % (", ".join(str(n - 1 - i) for i in capped), MAX_LAYER_ENTRIES))
    erred = sum(len(v["errors"]) for v in stats["layer_info"].values())
    if erred:
        problems.append("%d director(ies) or entr(ies) could not be read" % erred)
    if any(v.get("deep") for v in stats["layer_info"].values()):
        problems.append("a directory deeper than %d components was not entered" % MAX_DEPTH)
    pages = {"view": page.finish()}
    capped_text = capped_why(pages, None)
    if capped_text:
        problems.append(capped_text)
    if materialised is not None and any(not r["copied"] for r in materialised):
        problems.append("%d file(s) asked for were not copied (see copied)" % sum(1 for r in materialised if not r["copied"]))
    opaque_unknown = [r["layer"] for r in layers_report if r.get("state") == "read" and r["native_whiteouts"] and not str(r["xattrs"]).startswith("readable")]
    outcome = status_of(not problems, False, "every layer of the chain was read to its end and the view was built from all of them", "; ".join(problems) or "partial", "")
    out = {"parser": PARSER, **outcome, "layers_total": n, "layer_order": "layer 0 is the base; higher numbers are applied on top; the writable layer, when there is one, is the highest",
           "layers": layers_report, "missing_layers": missing, "chain_notes": notes + ([chain_problem] if chain_problem else []),
           "paths_in_view": len(paths), "paths_visible": sum(1 for r in paths.values() if r["supplier"] is not None),
           "path_prefix": prefix,
           "whiteout_kinds": {"oci": "a file named .wh.<name> deletes <name> below it; .wh..wh..opq makes the directory opaque (ordinary files: they survive extraction)",
                              "overlayfs_native": "a character device 0/0 is a whiteout and the xattr trusted.overlay.opaque (user.overlay.opaque, rootless) = y makes a directory opaque; extraction often loses the attribute and may not create devices",
                              "opaque_directories_not_told_in_layers": opaque_unknown,
                              "note": "for a layer whose xattrs are not readable here, a directory that was opaque in the original cannot be told from an ordinary one: its lower contents may show as visible"},
           "materialised": materialised, "view": page.page, "pages": pages, "truncated": pages["view"]["truncated"],
           "note": "the view is built from the layer directories as they are on disk: it is not a mounted overlay and does not show what a running container saw. A path's changes name the layers (from the base) that added, replaced or deleted it."}
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
    try:
        sys.stdout.write(json.dumps({"parser": PARSER, "error": "the tool stopped on an unexpected %s" % type(exc).__name__, "status": "failed",
                                     "status_basis": "an internal error ended the tool before it built an answer: nothing here is a complete result",
                                     "paging_files_kept": kept}) + "\n")
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
