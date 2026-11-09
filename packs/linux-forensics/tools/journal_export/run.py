#!/usr/bin/env python3
"""Read the evidence's journal, and never your own; keep every field of every entry.

journalctl with no arguments reads the journal of the machine you are sitting at. That is the easiest
mistake to make here, and its output looks entirely plausible in a report, so this tool refuses to run
without a path, passes it to `--file` or `--directory`, and puts the argv it ran (as an array) in its
answer. The journal carries what /var/log/auth.log does not: _EXE and _CMDLINE for the process that logged,
_SYSTEMD_UNIT for the service, _AUDIT_SESSION for the login session, and two clocks.

The two clocks are the point. __REALTIME_TIMESTAMP is the wall clock, which can be set, stepped, corrected by
NTP and wrong; __MONOTONIC_TIMESTAMP counts from the boot and is the order within it. A boot id names a boot
and orders nothing, so grouping by boot does not remove a clock step inside a boot, and across boots the two
clocks must be anchored independently. Both are kept raw, with the cursor (which names the entry and holds
the boot, the monotonic and the realtime values it was taken from) and the machine id.

What is kept. The complete native export (`journalctl -o json --all`) is written exactly as journalctl
produced it, one entry per line, to $OUT/journal-native.jsonl when `write_text: true` is asked in a job: it is
the lossless result, and it holds messages and command lines. The answer carries a projection of each entry:
the cursor, both clocks (raw and decoded), the boot and the machine, and the identity fields; a value that
journalctl wrote as a byte array or as null is named as such and never turned into text. It carries the
length of the message and of the command line, not their text.

THE SECRET-SAFE OUTPUT PATTERN (docs/packs.md, "Secrets and sensitive output"). A journal holds command lines
(_CMDLINE, sudo and mount messages) and application messages that can hold a password or a token. The answer
never carries `message` or `cmdline`; `preview_text: true` (in a job) adds them to the projection, and
`write_text: true` (in a job) writes the native entries to a private file. Both are refused outside a job; the
skill says the job runs with secret_output: true. Nothing is hashed or shortened.

A tool that fails loudly: journalctl's stderr is kept whole in a file; a deadline (`max_seconds`) ends the read
and returns what was read with `status: partial`; a line that is not JSON is counted and located; a
journalctl that failed and wrote nothing is an error, not an empty export. `mode: verify` runs journalctl
--verify on its own, keeps its whole output, and claims only what that command checks.

Processes. journalctl runs in this tool's own process group, not a session of its own: the harness ends a tool
that runs too long, or is aborted, by killing the tool's group, and a journalctl in a group of its own would go on
running after the tool is gone. The deadline (max_seconds, at most 270 of the manifest's 300) and SIGTERM, SIGINT
and SIGHUP end journalctl and what it started.
"""
import datetime
import hashlib
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
from pathlib import Path

TOOL = "journal_export"
PARSER = "journal_export/20"
DEFAULT_LIMIT = 200
DEFAULT_SECONDS = 240.0
MAX_SECONDS = 270.0           # the most a caller may ask for (the manifest allows 300)
MAX_WALK_ENTRIES = 100000     # a journal directory holds a few hundred files; a directory with more entries than this is not one, and is not walked on
FIRST_FAILURES = 20
MAX_BOOTS = 5000
MAX_BOOT_ID = 128          # a boot id is 32 hexadecimal digits; a longer one is counted and not grouped
MAX_LINE = 32 << 20       # an entry longer than this is counted and located, not parsed
PREVIEW_CHARS = 65536     # a previewed message or command line is shown to this many characters, with its whole length
OWN_JOURNALS = ("/var/log/journal", "/run/log/journal")
MAX_FIELD_NAMES = 500
TEXT_NAME = "journal-native.jsonl"
VERIFY_NAME = "journal-verify.txt"
STDERR_NAME = "journalctl.stderr"
EPOCH = datetime.datetime(1970, 1, 1)
# A time bound is read by journalctl in the zone of the machine running it, which is not the evidence's: only a
# bound that carries its own zone is passed on (the UTC suffix, or seconds since the epoch).
BOUND = re.compile(r"^(?:@\d+(?:\.\d+)?|\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}(?::\d{2}(?:\.\d+)?)?\s+UTC)$")


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


# journal_export's stop is the SHARED PROCESS block above, which has no deferral of a signal during a write; the parts below are written for
# the stop of LINUX STOP and need these two names, which here do nothing.
def _writing():
    pass


def _written():
    pass


MACHINE_ID_FILES = ("/etc/machine-id", "/var/lib/dbus/machine-id")
JOURNAL_MAGIC = b"LPKSHHRH"
JOURNAL_MACHINE_ID_AT = 40          # the machine_id field of the journal file header (systemd's journal file format: 16 bytes at offset 40)
MAX_OWN_CHECK_FILES = 200           # how many journal files are read for their machine id
MAX_OWN_CHECK_ENTRIES = 5000        # how many directory entries are looked at to find them (no link is followed)


def this_machines_id():
    """The 32 hex digits of this machine's id, or None where it cannot be read."""
    for name in MACHINE_ID_FILES:
        try:
            with open(name, "rb") as fh:
                text = fh.read(64).decode("ascii", "replace").strip().lower()
        except OSError:
            continue
        if re.fullmatch(r"[0-9a-f]{32}", text):
            return text
    return None


def journal_machine_ids(path):
    """The machine ids (32 hex digits) that the journal files at `path` carry in their headers: `path` is a journal file or a directory,
    searched below for files that begin with the journal signature, without following a link, within MAX_OWN_CHECK_FILES files and
    MAX_OWN_CHECK_ENTRIES entries. An all-zero id is no id."""
    found, files, entries = set(), 0, 0
    stack = [path]
    while stack and files < MAX_OWN_CHECK_FILES and entries < MAX_OWN_CHECK_ENTRIES:
        here = stack.pop()
        try:
            if os.path.isdir(here) and not os.path.islink(here):
                with os.scandir(here) as listing:
                    for entry in listing:
                        entries += 1
                        if entries >= MAX_OWN_CHECK_ENTRIES:
                            break
                        if entry.is_dir(follow_symlinks=False):
                            stack.append(entry.path)
                        elif entry.is_file(follow_symlinks=False):
                            stack.append(entry.path)
                continue
            if os.path.islink(here) or not os.path.isfile(here):
                continue
            files += 1
            fd = os.open(here, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0))
            try:
                head = os.read(fd, JOURNAL_MACHINE_ID_AT + 16)
            finally:
                os.close(fd)
        except (OSError, ValueError):
            continue
        if head[:8] == JOURNAL_MAGIC and len(head) >= JOURNAL_MACHINE_ID_AT + 16:
            ident = head[JOURNAL_MACHINE_ID_AT:JOURNAL_MACHINE_ID_AT + 16]
            if any(ident):
                found.add(ident.hex())
    return found


def is_own_journal(path, own_journals=None, machine_id="this machine"):
    """Whether the journal at `path` (a file, or a directory with journal files below it) is this machine's own: the machine id its files
    carry in their headers is the id in this machine's /etc/machine-id, or the directory is named by that id (/var/log/journal/<id>).
    The place is not the test: a run directory under /var/log/journal holds evidence whatever its prefix, and a copy of this machine's own
    journal is found wherever it was put. Only where this machine's id cannot be read is the old test used, the place (`own_journals`
    and the places the path is a link to), since nothing else can tell. `machine_id` is this machine's id for a caller that knows it."""
    mine = this_machines_id() if machine_id == "this machine" else machine_id
    if mine is None:
        own_journals = OWN_JOURNALS if own_journals is None else own_journals
        spellings = {os.path.abspath(path), os.path.realpath(path)}
        homes = set(own_journals) | {os.path.realpath(o) for o in own_journals}
        return any(spelling == home or spelling.startswith(home.rstrip(os.sep) + os.sep) for spelling in spellings for home in homes)
    return os.path.basename(os.path.realpath(path)).lower() == mine or mine in journal_machine_ids(path)


def refuse_root_directory(path):
    """A directory that is the root of the file system (spelled however, or reached through a link such as /proc/self/root) is a whole
    file system and not a journal: it is refused before anything below it is looked at."""
    if os.path.isdir(path) and os.path.realpath(path) == os.sep:
        fail("refusing the root directory: it is a whole file system, not a journal. Pass the journal's own directory (such as "
             "var/log/journal/<machine id>) or its .journal files", path=path)


def look_for_links(top, deadline):
    """(links found, entries looked at, why the walk ended early or None): every entry below `top` is examined with lstat and no link
    is followed. The clock is read for every entry and the walk ends at MAX_WALK_ENTRIES, so a directory that is not a journal's
    (a whole file system passed by mistake) costs a bounded time. Names are listed lazily (scandir), so one directory of millions
    of entries is not read whole before the first look at the clock."""
    links, looked, stack = [], 0, []
    try:
        stack.append(os.scandir(top))
    except OSError as exc:
        return links, looked, "the directory could not be listed: %s" % describe(exc)
    try:
        while stack:
            try:
                entry = next(stack[-1])
            except StopIteration:
                stack.pop().close()
                continue
            except OSError as exc:
                return links, looked, "a directory could not be listed: %s" % describe(exc)
            looked += 1
            if time.monotonic() > deadline:
                return links, looked, "max_seconds passed after %d entries, in %s" % (looked, os.path.dirname(entry.path))
            if looked > MAX_WALK_ENTRIES:
                return links, looked, "more than %d entries were met, in %s: this is not a journal directory" % (MAX_WALK_ENTRIES, os.path.dirname(entry.path))
            try:
                if entry.is_symlink():
                    links.append(entry.path)
                elif entry.is_dir(follow_symlinks=False):
                    stack.append(os.scandir(entry.path))
            except OSError as exc:
                return links, looked, "%s could not be examined: %s" % (entry.path, describe(exc))
    finally:
        for it in stack:
            it.close()
    return links, looked, None


def decoded_time(micro):
    try:
        return (EPOCH + datetime.timedelta(microseconds=int(micro))).isoformat() + "Z", None
    except (ValueError, TypeError, OverflowError):
        return None, "__REALTIME_TIMESTAMP %s is not a count of microseconds in the range of a date" % (bound(repr(micro), 200)[0],)


def sized(value):
    """(bytes, encoding) of a field journalctl wrote as a string, a byte array, a list of values or null."""
    if value is None:
        return 0, "null"
    if isinstance(value, str):
        return blen(value), "text"
    if isinstance(value, list) and all(isinstance(x, int) for x in value):
        return len(value), "bytes"
    if isinstance(value, list):
        return sum(blen(str(x)) for x in value), "several values"
    return blen(str(value)), "other"


SHOWN_VALUES = 5       # of a field that holds several values, the first this many are shown; the count says how many there are


def shown_field(value):
    """(what the row shows of a field, the whole length in characters when it was cut or None). A string is cut at 1024
    characters; a number, a boolean and null are shown; a byte array (journalctl writes a field that is not UTF-8 as one) is
    named by its length and never turned into text or into numbers; a list of several values shows its first few, cut the
    same way, and its count; anything else is named by its kind. The whole entry is in the native file."""
    if value is None or isinstance(value, (bool, int, float)):
        return value, None
    if isinstance(value, str):
        return bound(value, 1024)
    if isinstance(value, list) and all(isinstance(x, int) and not isinstance(x, bool) for x in value):
        return {"encoding": "bytes", "bytes": len(value)}, None
    if isinstance(value, list):
        first = [shown_field(x)[0] if isinstance(x, (str, int, float, bool)) or x is None else {"encoding": "other"} for x in value[:SHOWN_VALUES]]
        return {"encoding": "several values", "values": len(value), "first": first}, None
    return {"encoding": "other", "bytes": blen(str(value))}, None


IDENTITY = (("_PID", "pid"), ("_UID", "uid"), ("_GID", "gid"), ("_COMM", "comm"), ("_EXE", "exe"),
            ("_SYSTEMD_UNIT", "unit"), ("_SYSTEMD_USER_UNIT", "user_unit"), ("_AUDIT_SESSION", "audit_session"),
            ("_AUDIT_LOGINUID", "audit_loginuid"), ("SYSLOG_IDENTIFIER", "syslog_identifier"), ("PRIORITY", "priority"),
            ("_TRANSPORT", "transport"), ("_HOSTNAME", "hostname"), ("_MACHINE_ID", "machine_id"))


def project(entry, number, seq):
    realtime = entry.get("__REALTIME_TIMESTAMP")
    shown, error = decoded_time(realtime) if realtime is not None else (None, "no __REALTIME_TIMESTAMP")
    msg_bytes, msg_enc = sized(entry.get("MESSAGE"))
    cmd_bytes, cmd_enc = sized(entry.get("_CMDLINE"))
    row = {"id": "J%06d" % seq, "parser": PARSER, "native_line": number}
    cut = {}

    def put(name, value):
        shown_, whole = shown_field(value)
        row[name] = shown_
        if whole is not None:
            cut[name] = whole
    put("cursor", entry.get("__CURSOR"))
    put("realtime_us", realtime)
    row["time"] = shown
    put("monotonic_us", entry.get("__MONOTONIC_TIMESTAMP"))
    put("boot_id", entry.get("_BOOT_ID"))
    if error:
        row["time_error"] = error
    for field, name in (("_SOURCE_REALTIME_TIMESTAMP", "source_realtime_us"), ("_SOURCE_MONOTONIC_TIMESTAMP", "source_monotonic_us"),
                        ("__SEQNUM", "seqnum"), ("__SEQNUM_ID", "seqnum_id")):
        if field in entry:
            put(name, entry[field])
    for field, name in IDENTITY:
        if field in entry:
            put(name, entry[field])
    if cut:
        row["truncated_fields"] = cut
    row.update({"message_bytes": msg_bytes, "message_encoding": msg_enc})
    if "_CMDLINE" in entry:
        row.update({"cmdline_bytes": cmd_bytes, "cmdline_encoding": cmd_enc})
    return row


def output_file(name):
    """Where a whole output of this tool is kept: $OUT in a job, work/<agent>/tool-output otherwise. A name already taken
    (a second call in one job) is never overwritten: it gets a number before its extension."""
    job, out = os.environ.get("JOB_ID"), os.environ.get("OUT")
    if job and out:
        base = Path(out)
        shown_dir = "store/jobs/%s/out" % re.sub(r"[^A-Za-z0-9_.-]", "_", job)
    else:
        agent = re.sub(r"[^A-Za-z0-9_.-]", "_", os.environ.get("AGENT_ID") or "tool")
        base = Path("work") / agent / "tool-output"
        shown_dir = str(base)
        name = "%s-%s-%s" % (TOOL, secrets.token_hex(8), name)
    try:
        base.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        fail("the output directory %s cannot be created: %s" % (base, describe(exc)))
    stem, dot, ext = name.partition(".")
    for n in range(0, 1000):
        candidate = name if n == 0 else "%s.%d%s%s" % (stem, n + 1, dot, ext)
        try:
            fd = os.open(str(base / candidate), os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        except FileExistsError:
            continue
        except OSError as exc:
            fail("the output file %s cannot be created: %s" % (base / candidate, describe(exc)))
        os.close(fd)
        return base / candidate, "%s/%s" % (shown_dir, candidate)
    fail("no free name for %s in %s" % (name, base))


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


def run_journalctl(argv, raw_sink, line_sink, oversized_sink, stderr_path, seconds):
    """Run journalctl in this tool's process group (spawn, below: the harness ends a tool by killing its group), with a
    deadline that ends it and what it started. Every byte of stdout goes to `raw_sink` in order; each line within MAX_LINE
    goes whole to `line_sink`, and a longer one is counted by `oversized_sink` and not held, so one huge entry costs no more
    memory than the cap. The pipe is read with select, so the deadline needs no thread."""
    timed_out = False
    with open(stderr_path, "wb") as err:
        proc = spawn(argv, stdout=subprocess.PIPE, stderr=err)
        ACTIVE.append(proc)
        try:
            fd = proc.stdout.fileno()
            end = time.monotonic() + seconds
            pending, size = [], 0
            exited, release = None, None
            while True:
                left = end - time.monotonic()
                if left <= 0 and not timed_out:
                    # The deadline: end journalctl and what it started, then take what is left in the pipe.
                    timed_out = True
                    kill_tree(proc)
                    end = time.monotonic() + 5.0
                    continue
                if left <= 0:
                    break
                now = time.monotonic()
                if release is not None and now >= release:
                    break           # the holder was ended and the pipe still has no end: it is let go
                if exited is None and proc.poll() is not None:
                    exited = now    # counted from journalctl's end whether bytes keep coming or not: a leftover that writes slowly does not hold the tool to its deadline
                if release is None and exited is not None and now - exited >= PIPE_GRACE:
                    reap_orphans(_pipe_inodes(proc))
                    settle()        # a process that holds the pipe is ended (program_group.left_behind), and the pipe gets its end
                    release = time.monotonic() + 1.0
                ready, _w, _x = select.select([fd], [], [], min(left, 0.2))
                if not ready:
                    continue
                chunk = os.read(fd, 1 << 20)
                if not chunk:
                    break
                raw_sink(chunk)
                start = 0
                while start < len(chunk):
                    nl = chunk.find(b"\n", start)
                    part = chunk[start:] if nl < 0 else chunk[start:nl + 1]
                    start += len(part)
                    size += len(part)
                    if pending is not None and size <= MAX_LINE:
                        pending.append(part)
                    else:
                        pending = None
                    if part.endswith(b"\n"):
                        if pending is None:
                            oversized_sink(size)
                        else:
                            line_sink(b"".join(pending))
                        pending, size = [], 0
            if size:
                if pending is None:
                    oversized_sink(size)
                else:
                    line_sink(b"".join(pending))
        finally:
            if proc.poll() is None:
                kill_tree(proc)
            proc.stdout.close()
            proc.wait()
            ACTIVE.remove(proc)
    return proc.returncode, timed_out


def size_and_sha256(path):
    """(bytes, sha256 hex) of journalctl's stderr file: the answer names the file and says how long it is and which bytes it holds, and never quotes
    its lines (they can carry paths and the text of entries). (None, None) where the file cannot be read."""
    digest, size = hashlib.sha256(), 0
    try:
        with open(path, "rb") as fh:
            for block in iter(lambda: fh.read(1 << 20), b""):
                digest.update(block)
                size += len(block)
    except OSError:
        return None, None
    return size, digest.hexdigest()


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
    path = want_str(args, "path", "path is required: journalctl with no path reads this machine's own journal, which is never the evidence")
    try:
        present = os.path.lexists(path)
        if present and os.path.islink(path):
            fail("refusing a symlink: pass the journal file or directory inside the evidence", path=path, target=os.readlink(path))
        mode_bits = os.stat(path).st_mode if present else 0
    except OSError as exc:
        fail("the path cannot be examined", path=path, reason=describe(exc))
    if not present:
        fail("no such file or directory", path=path)
    if not (stat.S_ISREG(mode_bits) or stat.S_ISDIR(mode_bits)):
        fail("not a journal file or a directory: a pipe, a socket or a device is never passed to journalctl", path=path)
    absolute = os.path.abspath(path)
    here = os.getcwd()
    inside_run = absolute == here or absolute.startswith(here + os.sep)
    if not inside_run and is_own_journal(path):
        fail("this path is where this machine keeps its own journal (or leads there through a link), which is never the evidence: "
             "pass the journal under inputs/ or work/", path=path)
    if inside_run:
        # Every component under the run directory must be a real directory or file: a link in the middle of the path can lead out of the evidence.
        walked = here
        for part in os.path.relpath(absolute, here).split(os.sep):
            if part in (".", ""):
                continue
            walked = os.path.join(walked, part)
            if os.path.islink(walked):
                fail("refusing a path that goes through a link (%s): pass the journal's real location inside the evidence" % walked, path=path, link=walked)
    refuse_root_directory(path)
    refuse_disk_image(path, "path")
    mode = args.get("mode", "export")
    if mode not in ("export", "verify"):
        fail("mode must be export or verify")
    limit = want_limit(args)
    write_text, preview_text = want_flag(args, "write_text"), want_flag(args, "preview_text")
    if preview_text:
        require_job("preview_text")
    seconds = want_seconds(args, "max_seconds", DEFAULT_SECONDS, MAX_SECONDS)
    started = time.monotonic()      # max_seconds covers the whole call: the walk below and journalctl share it
    if args.get("grep") and not in_job():
        fail("grep is refused outside a job: it matches the text of the messages, which this answer withholds, so a count of what "
             "it matched would be an oracle on that text. Run this as job_run tool=journal_export with secret_output: true, and ask again there.")
    for name in ("unit", "grep", "priority", "since", "until"):
        given = want_str(args, name)
        if given is not None:
            # These become arguments of journalctl: a NUL byte or a lone surrogate cannot be one (it would end the call with a traceback).
            try:
                given.encode("utf-8")
            except UnicodeEncodeError:
                fail("%s holds a character that is not text (a lone surrogate): journalctl cannot be given it" % name)
            if "\x00" in given:
                fail("%s holds a NUL byte: journalctl cannot be given it" % name)
    bounds = {}
    for key in ("since", "until"):
        if args.get(key):
            if not BOUND.match(args[key].strip()):
                fail("%s must carry its own zone: journalctl reads a bare time in the zone of the machine it runs on, which is "
                     "not the evidence's. Write it as 'YYYY-MM-DD HH:MM:SS UTC' or as seconds since the epoch, '@1771100000'." % key,
                     given=args[key])
            bounds[key] = args[key].strip()
    binary = shutil.which("journalctl")
    if not binary:
        fail("journalctl is not on PATH",
             install="apt-get install -y systemd; the journal is a binary format that journalctl reads",
             note="On macOS there is no journalctl at all: copy the journal to a Linux host.")
    if os.path.isdir(path):
        links, looked, stopped = look_for_links(path, started + seconds)
        if links:
            fail("refusing a journal directory that holds links: journalctl --directory may follow them out of the evidence. "
                 "Pass each real journal file as path instead.", links=links[:FIRST_FAILURES], link_count=len(links),
                 entries_looked_at=looked, walk_ended_early=stopped)
        if stopped:
            fail("the directory could not be checked for links, so journalctl was not run on it: %s. Pass the journal's own directory "
                 "(such as var/log/journal/<machine id>) or its .journal files, not a directory that holds more than a journal." % stopped,
                 path=path, entries_looked_at=looked, walk_ended_early=stopped)
    where = ["--directory" if os.path.isdir(path) else "--file", path]

    if mode == "verify":
        argv = [binary, "--verify"] + where
        out_path, out_shown = output_file(VERIFY_NAME)
        err_path, err_shown = output_file(STDERR_NAME)
        install_signal_handlers()
        try:
            with open(out_path, "wb") as sink:
                STATE["last_word"] = lambda signum: sink.flush()
                code, timed_out = run_journalctl(argv, sink.write, lambda raw: None, lambda size: None, err_path, max(1.0, seconds - (time.monotonic() - started)))
        except OSError as exc:
            fail("journalctl could not be run: %s" % describe(exc), argv=argv)
        # the output is journalctl's, copied from the pipe by this tool, and its stderr is a file journalctl wrote: a process it left behind (ended by settle() before the files were
        # sized and hashed), or one that cannot be ruled out (not Linux, PR_SET_CHILD_SUBREAPER refused), keeps the answer from `complete`
        group = program_group_problems("the output and the stderr file")
        outcome = status_of(not timed_out and not group, False,
                            "journalctl --verify ran to its end; its exit code and whole output are kept (a clean result is not a complete journal)",
                            "; ".join((["journalctl --verify did not finish within max_seconds: the output so far is kept"] if timed_out else []) + group), "")
        print(json.dumps({
            "parser": PARSER, "mode": "verify", **outcome, "program_group": process_verdict(), "problems": group, "path": path, "argv": argv, "exit_code": code, "timed_out": timed_out,
            "verify": {"output_file": out_shown, "output_bytes": os.path.getsize(out_path), "stderr_file": err_shown,
                       "stderr_bytes": size_and_sha256(err_path)[0], "stderr_sha256": size_and_sha256(err_path)[1]},
            "claims": "journalctl --verify checks the internal, structural consistency of the journal files it was given, and, "
                      "for a sealed journal with the verification key, the seal. The exit code and the whole output are kept.",
            "does_not_show": "that no journal file or entry is missing or was removed, that the host kept a persistent journal, "
                             "that an unsealed journal is authentic, or that the entries say what happened: a clean result is "
                             "not a complete one. Read the output for each file, and judge gaps against rotation, retention, "
                             "the boundaries of what was collected and any remote copy.",
        }, indent=2))
        return

    try:
        text = TextFile(TEXT_NAME, write_text, "the native `journalctl -o json --all` output, exactly as journalctl wrote it, one entry per line")
    except TextRefused as exc:
        fail(str(exc))
    argv = [binary] + where + ["-o", "json", "--no-pager", "--all", "--quiet"]
    for flag, name in (("--unit", "unit"), ("--since", "since"), ("--until", "until"), ("--grep", "grep"), ("--priority", "priority")):
        value = bounds.get(name) if name in ("since", "until") else args.get(name)
        if value:
            argv += [flag, str(value)]
    err_path, err_shown = output_file(STDERR_NAME)
    page = LosslessPage(TOOL, "records", limit)
    preview_rows = []
    census, boots = {}, {}
    st = {"lines": 0, "entries": 0, "bad": [], "bad_count": 0, "census_truncated": False, "boots_truncated": False,
          "oversized": 0, "boot_not_text": 0, "boot_overlong": 0}

    def oversized(size):
        text.count_record()
        st["lines"] += 1
        st["oversized"] += 1
        st["bad_count"] += 1
        if len(st["bad"]) < FIRST_FAILURES:
            st["bad"].append({"native_line": st["lines"], "bytes": size,
                              "error": "a line over %d bytes: counted and located, not parsed (its bytes are in the native file when write_text was asked)" % MAX_LINE})

    def sink(raw):
        text.count_record()
        st["lines"] += 1
        number = st["lines"]
        if raw.strip() in (b"-- No entries --", b"-- No entries --\r"):
            st["no_entries"] = st.get("no_entries", 0) + 1     # journalctl's own notice for an empty selection: no entry, no error
            return
        try:
            entry = json.loads(raw)
            if not isinstance(entry, dict):
                raise ValueError("an entry is a JSON object")
        except ValueError as exc:
            st["bad_count"] += 1
            if len(st["bad"]) < FIRST_FAILURES:
                st["bad"].append({"native_line": number, "bytes": len(raw), "error": str(exc)})
            return
        st["entries"] += 1
        for name in entry:
            # A field name is cut at 128 characters in the census (it can be as long as the entry); the native file has it whole.
            shown_name = name if len(name) <= 128 else "%s...(%d characters)" % (name[:128], len(name))
            if shown_name in census or len(census) < MAX_FIELD_NAMES:
                census[shown_name] = census.get(shown_name, 0) + 1
            else:
                st["census_truncated"] = True
        row = project(entry, number, st["entries"])
        boot = entry.get("_BOOT_ID")
        if boot is not None and not isinstance(boot, str):
            st["boot_not_text"] += 1     # a repeated _BOOT_ID comes as a list: it is not one boot, and is not grouped
            boot = None
        elif isinstance(boot, str) and len(boot) > MAX_BOOT_ID:
            st["boot_overlong"] += 1     # a boot id is 32 hexadecimal digits: a longer one is not grouped, and is counted
            boot = None
        if boot is not None:
            b = boots.get(boot)
            if b is None and len(boots) < MAX_BOOTS:
                b = boots[boot] = {"boot_id": boot, "entries": 0, "first_realtime_us": row["realtime_us"],
                                   "first_monotonic_us": row["monotonic_us"], "first_cursor": row["cursor"]}
            elif b is None:
                st["boots_truncated"] = True
            if b is not None:
                b["entries"] += 1
                b["last_realtime_us"], b["last_monotonic_us"], b["last_cursor"] = row["realtime_us"], row["monotonic_us"], row["cursor"]
        page.add(row)
        if preview_text and len(preview_rows) < limit:
            msg, msg_whole = bound(entry.get("MESSAGE"), PREVIEW_CHARS)
            cmd, cmd_whole = bound(entry.get("_CMDLINE"), PREVIEW_CHARS)
            extra = {"preview_truncated": {k: v for k, v in (("message", msg_whole), ("cmdline", cmd_whole)) if v is not None}} if (msg_whole or cmd_whole) else {}
            preview_rows.append({**row, "message": msg, "cmdline": cmd, **extra})

    install_signal_handlers()
    STATE["last_word"] = lambda signum: text.close()
    try:
        code, timed_out = run_journalctl(argv, text.add_bytes_raw, sink, oversized, err_path, max(1.0, seconds - (time.monotonic() - started)))
    except OSError as exc:
        text.close()
        fail("journalctl could not be run: %s" % describe(exc), argv=argv)
    text.close()
    stderr_bytes = os.path.getsize(err_path)
    if code != 0 and not timed_out and st["entries"] == 0:
        stderr_size, stderr_digest = size_and_sha256(err_path)
        fail("journalctl refused this journal", exit_code=code, stderr_file=err_shown, stderr_bytes=stderr_size, stderr_sha256=stderr_digest, argv=argv)
    pages = {"records": page.finish()}
    capped = capped_why(pages, text)
    # the native export is journalctl's output copied from the pipe by this tool, and its stderr is a file journalctl wrote: a process it left behind (ended by settle() before the
    # files were sized and hashed), or one that cannot be ruled out (not Linux, PR_SET_CHILD_SUBREAPER refused), keeps the answer from `complete`
    group = program_group_problems("the export and the stderr file")
    complete = code == 0 and not timed_out and st["bad_count"] == 0 and not capped and not group
    outcome = status_of(
        complete, False,
        "journalctl exited 0 within the deadline and every line it wrote parsed; this says nothing about journal files that were not in "
        "what you collected, or entries rotated away or never written",
        "journalctl exited %s%s and %d line(s) did not parse%s: what was read is kept and the files are named"
        % (code, " after the deadline" if timed_out else "", st["bad_count"], "; " + capped if capped else "") + ("; " + "; ".join(group) if group else ""), "")
    print(json.dumps({
        "parser": PARSER,
        "mode": "export",
        "program_group": process_verdict(),
        "problems": group,
        "path": path,
        "argv": argv,
        "time_bounds": {**bounds, "interpretation": "as written, with its own zone"} if bounds else None,
        "exit_code": code,
        "timed_out": timed_out,
        **outcome,
        "no_entries_notices": st.get("no_entries", 0),
        "grep_scope": None if not args.get("grep") else "the message text, in a job",
        "filter_touched_withheld_text": touches_withheld_text(bool(args.get("grep"))),
        "entry_count": st["entries"],
        "lines_read": st["lines"],
        "boots_seen": len(boots),
        "boots": list(boots.values()),
        "boots_truncated": st["boots_truncated"],
        "field_census": census,
        "field_census_truncated": st["census_truncated"],
        "parse_errors": {"count": st["bad_count"], "first": st["bad"], "oversized_lines": st["oversized"]},
        "entries_with_a_boot_id_that_is_not_text": st["boot_not_text"],
        "entries_with_a_boot_id_over_%d_characters" % MAX_BOOT_ID: st["boot_overlong"],
        "stderr": {"file": err_shown, "bytes": stderr_bytes, "sha256": size_and_sha256(err_path)[1]},
        "records": preview_rows if preview_text else page.page,
        "record_count": pages["records"]["matched"],
        "pages": pages,
        "text": text.summary(preview_text),
        "truncated": pages["records"]["truncated"],
        "note": "Within a boot, order entries by monotonic_us: the wall clock (realtime_us) can step inside a boot, and neither a boot "
                "id nor the order journalctl printed removes that. A boot id names a boot and does not order it; across boots, anchor "
                "the two clocks independently. The projection keeps the cursor and both clocks raw, and the whole entry is in the "
                "native file when write_text was asked. That no journal directory is in what you collected shows only that this path "
                "was not collected: it does not show that the host never kept a persistent journal or that earlier boots were never "
                "written, so read the journald configuration and the machine's other journals before saying so. mode: verify checks "
                "the structure of the files it is given and says nothing about files or entries that are not there.",
    }, indent=2))


if __name__ == "__main__":
    main()
