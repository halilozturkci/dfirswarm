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

The identity map (`identity`: passwd and group files of the EVIDENCE) names uids and gids; without it they stay numeric. This
analysis machine's /etc/passwd and /etc/group are never read.
"""
import datetime
import ipaddress
import json
import math
import os
import re
import secrets
import signal
import stat
import sys
import time
import zlib
from collections import OrderedDict
from pathlib import Path

TOOL = "audit_events"
PARSER = "audit_events/1"


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
    os._exit(128 + signum)


def install_signal_handlers():
    for signum in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(signum, _on_signal)


install_signal_handlers()
# END LINUX STOP
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

# BEGIN LINUX PARTS
# ---- The parts every tool of this pack that pages or keeps text copies (a tool is standalone; none imports another) ----
# The same text is in auth_log, cron_dump, journal_export, shell_history and utmp_parse (tests/pack-linux-parts.test.ts holds the copies
# equal). It uses STATE, _writing and _written, which are LINUX STOP's in four tools and, in journal_export, whose stop is its SHARED PROCESS
# block, two stand-ins below the SHARED PROCESS block's STATE.


def fail(message, **extra):
    """An error answer: JSON, exit 1, and the same `status` every answer of this pack carries."""
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


def run_read(paths, wanted, since, until, page, text_file, identity, clock, stats):
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
    seconds = want_seconds(args, "max_seconds", DEFAULT_SECONDS, MAX_SECONDS)
    clock = Clock(seconds)
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
    run_read(paths, wanted, since, until, page, text_file, names, clock, stats)
    text_file.close()
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
    outcome = status_of(read_all and lines_ok and not capped and identity_complete, False,
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
           "second_reader": {"status": "not_run", "why": "the standard-library reader is the only reader in this version"},
           "text": text_file.summary(), "events": page.page, "pages": pages, "truncated": pages["events"]["truncated"],
           "limits": LIMITS_NOTE}
    if clock.out:
        out["stopped_because"] = "max_seconds"
    out["receipt"] = write_receipt(out)
    STATE["answering"] = True
    print(json.dumps(out, indent=2))


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
    try:
        main()
    except SystemExit:
        raise
    except BaseException as exc:  # noqa: BLE001 - the last resort
        last_resort(exc)
