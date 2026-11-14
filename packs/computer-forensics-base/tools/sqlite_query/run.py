#!/usr/bin/env python3
"""Run a read-only SQL query over a SQLite database file, bounded and typed.

What this reads: the main database file, opened read-only and immutable, through
Python's sqlite3 module (never the sqlite3 shell). An authorizer lets a statement
read and nothing else: no write, no ATTACH, no extension, no PRAGMA that sets.
What it does not read: the write-ahead log of the file it is given. An immutable open ignores a -wal and
a -shm beside the database, so rows committed only in the WAL are not in the
result; the tool inventories the sidecars (name, size, WAL frames) and says so
in `snapshot_status`, loudly, instead of leaving it to be found. Applying a WAL
needs a staged copy of the database set, which this tool does not make: the
sqlite_snapshot tool does (it copies the set with hashes and has SQLite apply the
WAL in the copy, never beside the evidence), and `db_path` may be that snapshot's
directory or the database inside it. The answer then carries `snapshot` (what the
snapshot says it holds, and whether the file queried is still the one it recorded)
and `snapshot_status` says which state the rows are. `apply_wal` is not a
parameter here: asking for it is an error that names sqlite_snapshot.

The answer is bounded: an inline page of rows (`limit`, and a byte ceiling), and
when the result is more than that the whole of it in a JSON Lines file, named in
`rows_file`. Each row is typed: NULL is null, an integer or a real is a number,
text is a string (text that is not UTF-8 carries its bytes in base64 beside the
escaped form), a BLOB is {blob_b64, length, sha256}. `stdout` keeps the text form
of the inline page the old tool returned (CSV with a header, or the shell's
`|`-separated list), for the callers that read it.

VALUES TO A FILE (`write_values: true`). On a table that holds secrets (cookies, saved logins, tokens, keys, messages) an
inline page puts values in the agent's context. In this mode no value is ever in the answer: the row values of ONE table go to
a 0600 file under $OUT, and the answer carries locators (table, a row locator, column), counts, types and lengths.

  * It takes `table` (and optionally `columns`, `rowid_from`, `rowid_to`), NOT `sql`. A WHERE, LIKE, JOIN or any expression over
    a column whose values are withheld would be an oracle: one call is one bit of every row, and a few hundred calls confirm a
    guess. The mode therefore exports whole rows and takes no filter; the counts it prints are the table's (or the rowid
    range's), not a filter's. Rows are read from the table itself (NOT INDEXED) and in the table's own order, never in an
    index's, whose order would be the order of the indexed values; the order is said by an ORDER BY wherever the table has one
    that is total. SQLite reads a WITHOUT ROWID table through a covering index, NOT INDEXED or not, unless told the order, so
    every such table is ordered by its whole primary key with the key's own collations and directions: SQLite then reads the
    table's b-tree, or an index whose leading keys are that key, in the same order, and needs no sort (a sort would make the
    row at an OFFSET depend on more than the key). The answer's `n_ranks` names the columns whose values that order follows.
  * What locates a row, and what that guarantees, depends on the table (`table_kind`):
      - rowid: an ordinary rowid table. The rowid is SQLite's row key and no column's value: SQLite assigns it (one more than the
        largest, as a rule) unless the application set it in its INSERT, and what an application put there is the
        application's. The rows come in rowid order (n_ranks []), and `rowid_from`/`rowid_to` select by that key and by nothing
        a column holds.
      - alias: the table's one primary key column is declared INTEGER and SQLite keeps it in no index of its own (PRAGMA
        index_list), so SQLite makes that column the rowid: the rowid IS a value. It is never printed (answer, text form, locators
        file), no WHERE names it, and a rowid range is refused (`rowid_is_a_value`); rows are located by their position `n`.
        The rows are ordered by that key, so `n` ranks its values (which row holds the smaller one), and that is all it says
        of them. (`INTEGER PRIMARY KEY DESC` is not an alias: SQLite gives it an index, and the table is an ordinary one.)
      - without_rowid: no rowid, whatever its columns are named; located by `n`, a rowid range refused. Decided by SQLite
        (PRAGMA table_list's `wr`), or by the statement's own words where that pragma is missing. The rows come in primary-key
        order, so `n` ranks the primary key's values in the same way: for such a table the order is not independent of the
        values.
      - virtual: located by `n` in the order the module returns rows, which can be the order of a value (fts5vocab returns its
        terms sorted; n_ranks null: not known); the rowid (whatever the module makes it) is not printed and a range is refused.
        A module that cannot start under the read-only authorizer (fts5 on some SQLite builds) is the named state
        `virtual_table_unsupported`, said as JSON.
      - shadowed: a rowid table whose columns named rowid, oid and _rowid_ hide the rowid; located by `n`. Where one of its
        columns is the INTEGER PRIMARY KEY the rows are ordered by it (n ranks it, n_ranks names it); otherwise they come in
        storage order, the rowid's.
  * A cell is type:length. The length of an integer is the characters of its decimal form, so it tells its sign and order of
    magnitude (a PIN stored as an integer loses its leading zeros: 0123 is integer:3); a real's is the characters of Python's
    shortest repr, which does not (1e+20 is real:5, 12345.6 is real:7).
  * It follows the secret-safe output pattern of recovery_key_scan (docs/packs.md, "Secrets and sensitive output"): refused
    outside a job (JOB_ID and OUT set), and in a job the harness did not run as secret output (SECRET_OUTPUT=1 is set for the
    process of a secret job; the manifest makes a job of this tool with write_values one), as a JSON answer before anything is opened; the values file created once the table is
    found and its layout read, before the first row, with O_EXCL and O_NOFOLLOW and mode 0600 (a wrong table name, or a file
    that is not SQLite, leaves nothing behind; a second export in one job's $OUT is refused by name, never overwrites); no hash,
    digest or fragment of a value anywhere; a printed name that is shaped like a token withheld by the shared block below (the
    network pack's, byte for byte). The skill that sends the agent here says the job runs with `secret_output: true`.
  * Errors: nothing of a reading error is printed in this mode but what its code decides (sqlite_code). sqlite's message can
    quote a value (a generated column's json_extract quotes the value it failed on), and so can the class Python gives the
    error (a message that quotes bytes that are not UTF-8 arrives as a UnicodeDecodeError, with no code); every decision (the
    time budget, the authorizer, a value over the length limit) is taken on sqlite's result code, and on Python before 3.11,
    which gives none, on the text before the message's first quote matched whole against sqlite's fixed messages. The answer
    gives a fixed sentence and the row position; the class and the message go to the values file (the cell's line, or the end
    line when the export stopped). A row that cannot be read whole is read alone, and when that fails too, a cell at a time:
    each cell is tried alone, then every cell that can be read is read in one query (the same order, LIMIT 1 OFFSET n), so an
    exported row's cells are always one row's. A value longer than the length limit is recorded as value_too_large (its row,
    column, type and, where SQLite gives it without reading the value, its length), a cell sqlite cannot compute as
    unreadable, and the export goes on with the rest (at most PARTS_MAX rows read a cell at a time; a row none of whose cells
    can be read stops it, row_unreadable). Which cells are unreadable follows from the table's own expressions over its
    values, so it can say something of them; the schema is the evidence's, not the caller's.
  * A write that fails (a full disk) ends the export as JSON: ok false, reason values_file_error, exit 1 (a stop before the
    end is a failure, as network_log_summary says of a read that stopped early); the kept file is read back and the answer's
    counts (values_file_holds, secret_values, cells_with_a_value) are what it holds: its whole cell lines, the row of the last,
    a part of a line after them, and whether it has the end line a whole file ends with, so a file cut short (by a kill as
    well) is recognisable. A locators file that cannot be written leaves ok true and complete false (the values file is
    whole), and says what of it is left. row_count N means rows 1..N are in the locators file: a row is counted once its
    cells are written (a write that fails in row N+1 can leave that row's first lines in the values file; values_file_holds
    names the row of the last whole line).

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


import base64
import collections
import csv
import errno
import hashlib
import io
import json
import math
import os
import re
import sqlite3
import struct
import sys
import tempfile
import time
import urllib.parse
from pathlib import Path


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

import os as _os
import sys as _sys
import threading as _threading

# ---- the one protected printer of an answer (outside the shared block) ------------------------------------------------------------
# The stop signals are held while the answer is written, so that a signal cannot cut the document. A reader that stops taking it (a full
# pipe) would make that tool unkillable by SIGTERM: the held write is therefore bounded. If a stop signal is waiting when
# HELD_WRITE_SECONDS have passed, the tool says so on stderr and ends with 128 plus that signal; nothing is claimed about the answer.
HELD_WRITE_SECONDS = int(_os.environ.get("TOOL_HELD_WRITE_SECONDS") or 30)       # the environment variable is for the tests
_STOPS = (signal.SIGTERM, signal.SIGINT, signal.SIGHUP)


def _unstick():
    try:
        waiting = signal.sigpending()
    except (AttributeError, OSError):
        waiting = set()
    held = [s for s in _STOPS if s in waiting]
    if held:
        try:
            _os.write(2, ("the answer could not be written in %d seconds (the reader is not taking it); ended by the stop signal that was held\n" % HELD_WRITE_SECONDS).encode())
        except OSError:
            pass
        _os._exit(128 + int(held[0]))
    again = _threading.Timer(1.0, _unstick)
    again.daemon = True
    again.start()


ERROR_FLAGS = ("all_results_error", "all_matches_error", "receipt_error", "receipts_error", "rows_file_error", "rows_error", "invalid_lines_file_error",
               "write_error", "values_error")


def _flagged(node, depth=0):
    """The first error flag found in an answer (top level, and two levels of dicts below it), or None."""
    if not isinstance(node, dict) or depth > 2:
        return None
    for key in ERROR_FLAGS:
        if node.get(key):
            return key
    for value in node.values():
        found = _flagged(value, depth + 1)
        if found:
            return found
    return None


def _reconcile(answer):
    """status, complete and ok are one fact: an error flag in the answer (a file that should hold the rest could not be written) is not a
    complete answer, and a complete or ok that survives a partial or failed status is a wrong claim. Said once, here, for every answer."""
    if not isinstance(answer, dict):
        return
    flag = _flagged(answer)
    if flag and answer.get("status") == "complete":
        answer["status"] = "partial"
        basis = answer.get("status_basis")
        answer["status_basis"] = ("%s; but %s says part of what was asked for could not be kept" % (basis, flag)) if basis else "%s says part of what was asked for could not be kept" % flag
    if answer.get("status") in ("partial", "failed") or flag:
        if answer.get("complete") is True:
            answer["complete"] = False
    if answer.get("status") == "failed" and answer.get("ok") is True:
        answer["ok"] = False


# BEGIN SHARED TEMPS
# One lifecycle for the hidden temporary files of a run. A file is made by temp_create (or its name is registered with temp_hold before it is
# made), it is registered before anything else is done with it, and it stays registered until temp_done says it was renamed into place. What is
# still registered when the run ends is removed: by atexit on a normal end or any exception, by drop_temporaries in the last-resort handler, and
# by the stop signal's own cleanup, which removes the _tmp of every object in PAGES (a registered name is one such object).
import atexit
import tempfile

if "PAGES" not in globals():
    PAGES = []                 # objects with a hidden temporary file (_tmp) that a stop removes


class _HeldTemp:
    def __init__(self, name):
        self._tmp = name


def temp_hold(name):
    """Register a temporary file that is about to be made (or has been): it is removed on every way out unless temp_done is called."""
    held = _HeldTemp(os.fspath(name))
    PAGES.append(held)
    return held._tmp


def temp_create(directory, prefix, suffix=""):
    """tempfile.mkstemp with the new name registered at once: (fd, name)."""
    fd, name = tempfile.mkstemp(dir=os.fspath(directory), prefix=prefix, suffix=suffix)
    temp_hold(name)
    return fd, name


def temp_done(name):
    """The file was renamed into place (or is kept on purpose): it is no longer a temporary."""
    name = os.fspath(name)
    PAGES[:] = [p for p in PAGES if not (isinstance(p, _HeldTemp) and p._tmp == name)]


def temp_drop(name):
    """Remove one temporary now; False when it could not be removed (it stays registered, and the end of the run tries again)."""
    try:
        os.unlink(name)
    except FileNotFoundError:
        pass
    except OSError:
        return False
    temp_done(name)
    return True


def temp_replace(tmp, dest):
    os.replace(tmp, dest)
    temp_done(tmp)


def drop_temporaries():
    """Remove every temporary still registered (the pages being written and the held names); the names that could not be removed come back."""
    left = []
    for page in list(PAGES):
        tmp = None
        try:
            tmp = getattr(page, "_tmp", None)
            if tmp is not None:
                os.unlink(tmp)
        except FileNotFoundError:
            pass
        except Exception:   # noqa: BLE001 - every one is tried
            left.append(str(tmp))
    return left


atexit.register(drop_temporaries)
# END SHARED TEMPS


def _guarded_write(write):
    try:
        before = signal.pthread_sigmask(signal.SIG_BLOCK, set(_STOPS))      # before the timer thread exists, so that the thread holds them too
    except (AttributeError, ValueError, OSError):
        before = None
    watch = _threading.Timer(HELD_WRITE_SECONDS, _unstick)
    watch.daemon = True
    watch.start()
    try:
        write()
        _sys.stdout.flush()
    except BrokenPipeError:                       # the reader is gone: there is nobody to tell
        _os._exit(1)
    watch.cancel()
    if before is not None:
        # The document is whole. A stop that came while it was written is let go now: run as a program, the shared ENDS block has given it a
        # handler that does nothing (the answer stands, and the call ends with its own code); loaded as a module, the tool's own handler ends it
        # (128 plus the signal; the last word was cleared) with nothing more on stdout. The mask is also what an in-process caller (a test) had before.
        signal.pthread_sigmask(signal.SIG_SETMASK, before)


_shared_print_answer = print_answer


def print_answer(answer, **dumps_kwargs):
    _reconcile(answer)
    _guarded_write(lambda: _shared_print_answer(answer, **dumps_kwargs))


def _unexpected_tool(kind, value, _tb):
    """Last resort: an error nobody foresaw is an answer too. The hidden temporaries are removed first (a name that cannot be removed is said in the
    answer), then one JSON document with the class and, for a file-system error, its reason (a message can quote a name from the evidence), and
    exit 1; what was written before it is not claimed. A stop signal that arrives while this runs is held with the answer's write and is answered by
    this document and exit 1, not by 128 + the signal."""
    try:
        left = drop_temporaries()
        reason = getattr(value, "strerror", None) if issubclass(kind, OSError) else None
        said = ("a path or file could not be used: %s" % (reason or kind.__name__)) if issubclass(kind, (OSError, ValueError)) else "internal error: %s" % kind.__name__
        answer = {"tool": globals().get("TOOL"), "status": "failed", "error": said,
                  "status_basis": "the tool stopped on an error it did not foresee (%s); what it had written before is not claimed" % kind.__name__}
        if left:
            answer["temporaries_left"] = left[:10]
            answer["status_basis"] += "; hidden temporary files that could not be removed are listed in temporaries_left"
        print_answer(answer)
    except BaseException:       # noqa: BLE001 - nothing may stop the exit
        pass
    os._exit(1)


sys.excepthook = _unexpected_tool


def open_regular(path):
    """open(path, "rb") for a caller's path that was checked as a regular file a moment ago: opened without waiting (O_NONBLOCK) and looked at with
    fstat on the descriptor, so a FIFO or a device put in its place is refused and never waited on (a FIFO would hold the tool for ever)."""
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0))
    try:
        if os.fstat(fd).st_mode & 0o170000 != 0o100000:
            raise OSError(22, "is not a regular file (it changed after it was checked)")
    except BaseException:
        os.close(fd)
        raise
    return open(fd, "rb")


HELD_DB = []                                # the database's descriptor stays open as long as the connection


def connect_checked(db, uri):
    """Connect to the database that was checked, not to whatever is at its name now: the file is opened once (a FIFO put in its place is refused,
    not waited for) and SQLite is pointed at that open descriptor through /proc, so a swap between the check and SQLite's own open cannot reach it."""
    fh = open_regular(db)
    HELD_DB.append(fh)
    through = "/proc/self/fd/%d" % fh.fileno()
    if os.path.isdir("/proc/self/fd"):
        uri = "file:%s?mode=ro&immutable=1" % urllib.parse.quote(through)
    return sqlite3.connect(uri, uri=True)

PAGES = []                 # objects with a hidden temporary file (_tmp) that a stop removes

TOOL = {"name": "sqlite_query", "version": 20}
DEFAULT_LIMIT = 100
LIMIT_MAX = 10000
INLINE_BYTES = 64 * 1024          # the inline page's JSON and its text form, each, as they are sent (ASCII-escaped, counted in bytes)
RAW_BUFFER_MAX = 8 * 1024 * 1024  # the raw values of the inline page held in memory; past it the rest goes to the file only
FILE_BYTES = 2 * 1024 ** 3        # the whole-result file stops here, and says so
BUDGET_SECONDS = 25
BUDGET_MAX = 110
SQL_MAX = 64 * 1024               # bytes of UTF-8
HASH_MAX = 256 * 1024 * 1024
BLOB_INLINE = 256                 # a BLOB longer than this shows its head inline; the file holds all of it
VALUE_MAX = 64 * 1024 * 1024      # the longest string or BLOB (or whole row) read: sqlite refuses a longer one before it is in memory
STREAM_AT = 1024 * 1024           # a BLOB longer than this is hashed and encoded to the file in slices, never as one more copy
SLICE_BYTES = 3 * 256 * 1024      # a multiple of 3, so each slice's base64 joins the next without padding

# BEGIN SHARED WITHHOLDING
# The same text is in every tool that withholds identifier-shaped strings and credentials (the network, base, encrypted-containers,
# memory, virtualization, ransomware and reverse-engineering packs, and the three tools of the cloud pack), so that they withhold the
# same strings; the tests that hold the copies equal are tests/shared-blocks-census.test.ts (how many carry it),
# tests/pack-re-delta10.test.ts (every copy equal, found by the marker), tests/pack-network-withholding.test.ts,
# tests/pack-base-shared.test.ts, tests/pack-virtualization-shared.test.ts, tests/pack-re-process.test.ts and
# tests/pack-cloud-shared.test.ts. An identifier-shaped string is withheld wherever the tool would print one: a name, a path
# component, a URL, a message that quotes either; and a credential (a value given to a password, a token, a cookie, a pair, a
# switch) by the name it is given under. A carrier may set two names above this block: WITHHOLD_LIMIT, the length past which a text is
# withheld whole (65536 when it sets none), and WITHHOLD_TICK, a hook that long scans call and that may raise to end them at the
# carrier's deadline (none when it sets none). Nothing else in the block is a carrier's to change.
COUNTS = {"names": 0, "urls": 0, "text": 0}
# A run of name characters long enough to be a token. `=` is only a padding at the end (so a key= prefix stays);
# `/` joins pieces of a base64 token and is handled apart, below.
_RUN = re.compile(r"[A-Za-z0-9_+%-]{20,}={0,2}|[A-Za-z0-9_+%-]{14,}={2}")
_SLASHED = re.compile(r"[A-Za-z0-9_+/%-]{30,}={0,2}")
_HEX = re.compile(r"[0-9a-fA-F]{32,}")
# The prefixed secrets that one expression finds. A JWT is not among them: `eyJ` + 8 name characters + `.` + 8 + `.` + the rest, tried at
# every `eyJ`, runs to the end of the run of name characters and fails again at each next `eyJ` of a text made of them, which costs the
# square of the length. `_prefixed_spans` reads a JWT in one pass instead, and puts it in order with these.
_PREFIX_RULES = re.compile(r"(?:AKIA|ASIA)[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}"
                           r"|xox[abeprs]-[A-Za-z0-9-]{10,}|sk-[A-Za-z0-9_-]{20,}"
                           r"|(?i:basic|bearer)\s+[A-Za-z0-9+/=._~-]{8,}")
_JWT_RUN = re.compile(r"[A-Za-z0-9_-]+")
# User-info: after `//` (a URL, or a scheme-relative one), or bare as name:password@host. A mailto: address is not one.
_USERINFO = re.compile(r"(?<=//)[^/?#\s@]+(?=@)")
_BARE_USERINFO = re.compile(r"(?<![\w.%+:/-])(?!mailto:)[\w.%+-]{1,64}:[^\s/@:]{1,128}(?=@[\w\[])")


def _withheld(what, length, kind):
    COUNTS[kind] = COUNTS.get(kind, 0) + 1
    return ("<%s withheld %d characters>" % (what, length)) if what else ("<withheld %d characters>" % length)


def _token_run(run):
    """Is this run of name characters shaped like a token, and not like words, dates or versions?"""
    if _HEX.search(run):
        return True
    chunks = [(m.group()[0].isdigit(), m.start(), m.end()) for m in re.finditer(r"[A-Za-z]+|[0-9]+", run)]
    # digits packed between letters ("a9b2c7"), which words, dates and versions do not do
    packed = 0
    for i, (is_digit, start, end) in enumerate(chunks):
        if not is_digit or end - start > 3:
            continue
        before = i > 0 and not chunks[i - 1][0] and chunks[i - 1][2] == start
        after = i + 1 < len(chunks) and not chunks[i + 1][0] and chunks[i + 1][1] == end
        packed += 1 if before or after else 0
    if packed >= 3:
        return True
    letters = [c for c in run if c.isalpha()]
    case_flips = sum(1 for a, b in zip(letters, letters[1:]) if a.islower() != b.islower())
    if len(letters) >= 20 and case_flips >= max(8, 0.4 * len(letters)):
        return True
    if run.endswith("==") and len(run) >= 16:
        return True
    if run.endswith("=") and len(run) >= 24:
        return True
    return len(run) >= 40 and run.isalnum() and any(c.isdigit() for c in run) and any(c.isalpha() for c in run)


def _randomish(piece):
    """A piece of a path that is not a plain word: digits among letters, or capitals inside a word."""
    if len(piece) < 4 or "." in piece or re.fullmatch(r"[A-Z][a-z]+", piece):
        return False
    letters = [c for c in piece if c.isalpha()]
    mixed = any(c.islower() for c in letters) and any(c.isupper() for c in letters)
    return (any(c.isdigit() for c in piece) and bool(letters)) or mixed


_SPAN_PIECE = re.compile(r"[A-Za-z0-9_+%-]+")
# A text longer than this is withheld whole, by its length, and not examined: no name, path or URL is tens of thousands of characters
# long, and the answer says how long the text was. Every rule below reads a text of this length in well under a second whatever its
# characters are, so that no call of `scrub` or `token_spans` can run for long on a text a file chose; the limit is the backstop for
# a shape of text that no rule was tried on, and the rules themselves are linear.
TEXT_LIMIT = globals().get("WITHHOLD_LIMIT", 65536)


def _prefixed_spans(text, tail=None):
    """The spans of the prefixed secrets in the text (a vendor prefix, a JWT, `Basic`/`Bearer` and its value), left to right and apart,
    as one expression holding all of them would find them (the first match at each offset, the next search where the last ended), in
    time linear in the text. With `tail`, an expression matched where each span ends, the span takes what it matches.

    A JWT is read from the runs of name characters (`[A-Za-z0-9_-]+`), cut once: its head is the first `eyJ` of a run that is followed
    by 8 or more characters of that run, and it ends where the third part of the JWT does; every later `eyJ` of the run reads the same
    rest, so the first one is the one that matches and a run that does not hold a JWT is not read again for each `eyJ` in it."""
    from bisect import bisect_right
    size = len(text)
    starts, ends, rest = [], [], {}
    if "eyJ" in text:
        for m in _JWT_RUN.finditer(text):
            starts.append(m.start())
            ends.append(m.end())

    def jwt_end(r):      # where a JWT whose head is in run r ends, or -1: `.`, a run of 8 or more, `.`, then the rest of the next run
        if r not in rest:
            end, last = -1, ends[r] + 1
            if (last < size and text[last - 1] == "." and r + 1 < len(starts) and starts[r + 1] == last
                    and ends[r + 1] - last >= 8 and ends[r + 1] < size and text[ends[r + 1]] == "."):
                end = ends[r + 1] + 1
                if r + 2 < len(starts) and starts[r + 2] == end:
                    end = ends[r + 2]
            rest[r] = end
        return rest[r]

    def next_jwt(at):    # (start, end) of the first JWT that starts at or after `at`, or None
        while True:
            p = text.find("eyJ", at)
            if p < 0:
                return None
            r = bisect_right(starts, p) - 1
            if p + 11 <= ends[r] and jwt_end(r) >= 0:
                return p, jwt_end(r)
            at = ends[r]  # no `eyJ` further in this run can be a head either

    spans, at = [], 0
    other = _PREFIX_RULES.search(text)
    jwt = next_jwt(0) if starts else None
    while other is not None or jwt is not None:
        if other is not None and other.start() < at:      # it began inside the span just taken: look again from its end
            other = _PREFIX_RULES.search(text, at)
        elif jwt is not None and jwt[0] < at:
            jwt = next_jwt(at)
        else:
            start, end = other.span() if jwt is None or (other is not None and other.start() < jwt[0]) else jwt
            if tail is not None:
                end = tail.match(text, end).end()
            spans.append((start, end))
            at = end
    return spans


def _grow_spans(text, spans):
    """Each flagged span takes the random-looking pieces next to it across a `/`: the head of a token is not printed.

    One pass cuts the text into pieces (runs of name characters) and keeps where each starts and ends. A span then walks
    that array by index; a piece is judged once, and a walk that reaches a piece an earlier walk has settled stops there, so
    the work is linear in the text and no range is sliced or searched again. (Looking back with a search over everything
    before a piece costs the cube of the length for a name of many `/`-joined pieces.)"""
    from bisect import bisect_left
    starts, ends = [], []
    for m in _SPAN_PIECE.finditer(text):
        starts.append(m.start())
        ends.append(m.end())
    count, size = len(starts), len(text)
    judged_left, judged_right, settled_left, settled_right = {}, {}, {}, {}

    def padded(k):       # where piece k ends with the up to two `=` of padding after it
        e = ends[k]
        if e < size and text[e] == "=":
            e += 2 if e + 1 < size and text[e + 1] == "=" else 1
        return e

    def left_ok(j):
        if j not in judged_left:
            judged_left[j] = _randomish(text[starts[j]:ends[j]])
        return judged_left[j]

    def right_ok(k):
        if k not in judged_right:
            judged_right[k] = _randomish(text[starts[k]:padded(k)])
        return judged_right[k]

    def before(at):      # the piece that growing left from offset `at` takes, or -1. `$` also ends a match before a final line break.
        if at < 2 or text[at - 1] != "/":
            return -1
        for stop in ((at - 1, at - 2) if text[at - 2] == "\n" else (at - 1,)):
            j = bisect_left(ends, stop)
            if j < count and ends[j] == stop:
                return j if left_ok(j) else -1
        return -1

    def after(k):        # the piece that growing right from the end of piece k takes, or -1
        e = padded(k)
        if k + 1 >= count or e >= size - 1 or text[e] != "/" or starts[k + 1] != e + 1:
            return -1
        return k + 1 if right_ok(k + 1) else -1

    def settle(i, step, memo):
        trail = []
        while i not in memo:
            trail.append(i)
            j = step(i)
            if j < 0:
                memo[i] = i
                break
            i = j
        final = memo[i]
        for t in trail:
            memo[t] = final
        return final

    grown = []
    for start, end in spans:
        j = before(start)
        if j >= 0:
            start = starts[settle(j, lambda i: before(starts[i]), settled_left)]
        if end < size - 1 and text[end] == "/":
            k = bisect_left(starts, end + 1)
            if k < count and starts[k] == end + 1 and right_ok(k):
                end = padded(settle(k, after, settled_right))
        grown.append((start, end))
    return grown


def token_spans(text):
    if len(text) > TEXT_LIMIT:
        return [(0, len(text))]
    spans = _prefixed_spans(text)
    for m in _RUN.finditer(text):
        if _token_run(m.group()):
            spans.append(m.span())
    # A base64 token holds `/`: pieces too short to be one alone (an AWS-style secret has two) are caught as a whole.
    for m in _SLASHED.finditer(text):
        run = m.group()
        if "/" in run and sum(1 for p in run.split("/") if _randomish(p)) >= 3 and re.search(r"[0-9+]", run):
            spans.append(m.span())
    grown = _grow_spans(text, spans) if spans else []
    grown.sort()
    merged = []
    for start, end in grown:
        if merged and start <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
        else:
            merged.append((start, end))
    return merged


def token_shaped(text):
    return bool(token_spans(text))


# ---- credentials: a value is withheld by the name it is given under and by the text around it ----------------------------------
# The rules above find strings that are shaped like an identifier. These find a secret that has no shape, because of what it is
# assigned to (`password=`, a `Name`/`Value` pair, a `-Password` switch, `curl -u user:pass`, `mysql -pSECRET`), and the common
# token families, private key blocks and hashes of an account database. A name decides whether a value is a secret, a value
# decides nothing. Every rule runs in time linear in the text (a bounded stretch after each anchor, no nested repeat), and a
# carrier whose texts are long (a cloud log: a megabyte) sets WITHHOLD_TICK to a hook that ends the work at its deadline.
_CRED_CHECKSUM_NAME = re.compile(r"(?i)checksum|digest|sha[0-9]|md5|etag|crc[0-9]")
_CRED_REDACTED = re.compile(r"^\W*(?:hidden_due_to_security_reasons|redacted|masked|removed|\*+|x{3,}|\[\])\W*$", re.I)
_CRED_NOT_A_VALUE = frozenset(("true", "false", "null", "none", "nil", "undefined", "required", "optional", "enabled", "disabled"))
_CRED_EXACT = {
    "password", "newpassword", "oldpassword", "currentpassword", "passwd", "pwd", "passphrase", "passcode", "pin", "otp",
    "pass", "dbpass", "userpass", "adminpass", "rootpass", "plaintext",
    "secret", "clientsecret", "secretkey", "secretaccesskey", "awssecretaccesskey", "awssecretkey", "secretstring",
    "secretbinary", "secrettext", "secretvalue", "accesskeysecret",
    "sessiontoken", "securitytoken", "accesstoken", "refreshtoken", "idtoken", "bearertoken", "authtoken", "token",
    "tokencode", "mfacode", "verificationcode", "authorizationcode",
    "authorization", "proxyauthorization", "cookie", "setcookie", "apikey", "privatekey", "privatekeypem",
    "sharedaccesskey", "sharedaccesssignature", "accountkey", "primarykey", "secondarykey", "keyvalue", "masterkey",
    "storagekey", "subscriptionkey", "ocpapimsubscriptionkey",
    "connectionstring", "credential", "credentials", "assertion", "samlresponse", "mfasecret",
    "sastoken", "sassignature", "signature", "sig",
    "passwordhash", "nthash", "ntlmhash", "lmhash",
}
_CRED_SUFFIX = ("password", "passwd", "passphrase", "secret", "apikey", "privatekey", "sessiontoken", "securitytoken",
                "accesstoken", "refreshtoken", "clientsecret", "token", "secrettext", "secretkey", "secretaccesskey",
                "primarykey", "secondarykey", "accountkey", "sharedaccesskey", "subscriptionkey", "passwordhash",
                "ntlmhash", "nthash", "passcode", "signature", "cookie")
# a position or an idempotency key under a name that ends in `token`
_CRED_NOT_SECRET = ("nexttoken", "pagetoken", "continuationtoken", "paginationtoken", "nextpagetoken", "pagingtoken",
                    "startingtoken", "nextmarkertoken", "clienttoken", "clientrequesttoken", "idempotencytoken",
                    "nextforwardtoken", "nextbackwardtoken", "requesttoken")
_CRED_CONTAINERS = ("credential", "credentials")
_CRED_NAME_CACHE = {}
_CRED_NAME_KEYS = ("Name", "name", "Key", "key")
_CRED_VALUE_KEYS = ("Value", "NewValue", "OldValue", "value", "newValue", "oldValue")


def is_container_name(name):
    """`credentials` names a group of fields (an access key id, an expiry, a token): each is judged by its own name."""
    return re.sub(r"[^a-z0-9]", "", str(name).lower()) in _CRED_CONTAINERS


def name_is_sensitive(name):
    """Does a field or a parameter of this name hold a secret? (`Password`, `client_secret`, `x-api-key`; not `nextToken`.)"""
    hit = _CRED_NAME_CACHE.get(name)
    if hit is None:
        flat = re.sub(r"[^a-z0-9]", "", str(name).lower())
        hit = flat in _CRED_EXACT or (len(flat) > 6 and flat.endswith(_CRED_SUFFIX) and not flat.endswith(_CRED_NOT_SECRET))
        if len(_CRED_NAME_CACHE) < 20000:
            _CRED_NAME_CACHE[name] = hit
    return hit


_CRED_B64 = "A-Za-z0-9+/_-"
_CRED_B64_RUN = re.compile(r"(?<![%s])[%s]{128,}={0,2}(?![%s])" % (_CRED_B64, _CRED_B64, _CRED_B64))
_CRED_B64_EDGE = "(?<![A-Za-z0-9+/=_-])"
_CRED_B64_END = "(?![A-Za-z0-9+/=_-])"
# The names an assignment is recognised by. A long compound name may carry any prefix (dbPassword=, apiToken=, adminSecret:);
# a short one needs the edge of a word (sig= is not design=).
_CRED_STRONG = (r"password|passwd|passphrase|secret|api[_-]?key|access[_-]?token|refresh[_-]?token|id[_-]?token|session[_-]?token|"
                r"security[_-]?token|auth[_-]?token|bearer[_-]?token|account[_-]?key|shared[_-]?access[_-]?key|primary[_-]?key|"
                r"secondary[_-]?key|private[_-]?key|subscription[_-]?key|sas[_-]?token|password[_-]?hash|nt[_-]?hash|ntlm[_-]?hash|"
                r"lm[_-]?hash|client[_-]?secret|secret[_-]?access[_-]?key|secret[_-]?key|secret[_-]?text|secret[_-]?value|token|signature|plaintext")
_CRED_SHORT = r"(?<![A-Za-z0-9])(?:pwd|pass|sig|pin|otp|sas)"
_CRED_SEP = r"""(?:\\*["']|["'])?\s*(?:[:=]|%3[dD]|%3[aA])\s*"""
# a short name is a name only as `pwd=value` or `pass:value`: "pass: 3 attempts" is prose
_CRED_SEPS = r"""(?:\\*["']|["'])?(?:\s*(?:=|%3[dD])\s*|:(?=\S))"""
_CRED_NAME = r"(?:(?:%s)%s|%s%s)" % (_CRED_STRONG, _CRED_SEP, _CRED_SHORT, _CRED_SEPS)
_CRED_ARN_TAIL = re.compile(r"arn:[A-Za-z0-9-]+:[A-Za-z0-9-]+:[A-Za-z0-9-]*:[0-9]*:$")
_CRED_PAIR_WHY = "a value paired with a credential name"
_CRED_RULES = [
    # anchored at the start of a run and possessive, so that a megabyte of `eyJ` is read once, not once per `eyJ`
    ("a JSON Web Token", re.compile(r"(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{6,}+\.[A-Za-z0-9_-]{2,}+(?:\.[A-Za-z0-9_-]*+)?"), 0),
    ("a JSON Web Encryption token", re.compile(r"(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{6,}+(?:\.[A-Za-z0-9_-]*+){4}"), 0),
    ("a password in a URL", re.compile(r"(?i)(?<![A-Za-z0-9+.-])[a-z][a-z0-9+.-]{1,20}://[^\s:/@\"'<>\\]{0,256}:([^\s/\"'<>\\]{1,1024})@(?=[^\s/@\"'<>]{1,255})"), 1),
    ("an Azure Functions key", re.compile(r"""(?i)(?:x-functions-key["']?\s*[:=]\s*(?:\\*["'])?|[?&;]code=)([A-Za-z0-9_/+=-]{16,512})"""), 1),
    ("a private key block", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----(?:[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----|[\s\S]*)"), 0),
    ("a base64 block of key lines", re.compile(r"(?:[A-Za-z0-9+/]{60,80}={0,2}\r?\n){2,}[A-Za-z0-9+/]{2,80}={0,2}"), 0),
    ("an authorization header value", re.compile(
        r"""(?i)authorization["']?\s*[:=]\s*(?:\\*["'])?(?:(?:bearer|basic|digest|negotiate|ntlm|token)\s+)?([^\s"'&,;\\]{1,4096})"""), 1),
    ("a cookie header value", re.compile(r"""(?i)cookie["']?\s*[:=]\s*(?:\\*["'])?([^\r\n"'\\]{1,4096})"""), 1),
    ("a scheme and its credential", re.compile(r"(?i)\b(?:bearer|basic)\s+([A-Za-z0-9._~+/=-]{3,4096})|\b(?:negotiate|ntlm|digest)\s+([A-Za-z0-9._~+/=-]{24,4096})"), -2),
    ("a value assigned to a credential name (quoted)", re.compile(
        r"""(?i)%s\\*(["'])(.{1,4096}?)(?=\\*\1)""" % _CRED_NAME), 2),
    ("a value assigned to a credential name", re.compile(
        r"""(?i)%s((?:(?!%%26)[^\s"'&<>\\]){1,4096})""" % _CRED_NAME), 1),
    ("a value given to a credential switch", re.compile(
        r"""(?i)(?<![A-Za-z0-9_])-(?:password|pass|pwd|passphrase|secret|clientsecret|apikey|accesstoken|token)\s+(?:\\*(["'])(.{1,4096}?)(?=\\*\1)|([^\s"'-][^\s"']{0,4095}))"""), -1),
    ("a secret given to ConvertTo-SecureString", re.compile(
        r"""(?i)ConvertTo-SecureString\s+(?:\\*(["'])(.{1,4096}?)(?=\\*\1)|([^\s"'-][^\s"']{0,4095}))"""), -1),
    # `mysql -u<user> -p<password>`: with `-p` glued to its value, and only as an option of a MySQL or MariaDB client (`ssh -p 22`,
    # `nc -p 80` and `mysql -p` alone, which asks for the password, name a port or nothing). The options are read up to the next
    # command of the kind, so that a text of many of them is read once, not once for each
    ("a password given to a MySQL client", re.compile(
        r"""(?i:(?<![\w.-])(?:mysql|mysqldump|mysqladmin|mysqlcheck|mysqlimport|mysqlshow|mariadb|mariadb-dump|mariadb-admin)(?:\.exe)?(?=\s))(?:(?!(?i:mysql|mariadb)\b)[^\n]){0,512}?(?<=\s)-p(?=[^\s`,;)])(?:"([^"\n]{1,256})"|'([^'\n]{1,256})'|([^\s"']{1,256}))"""), -3),
    # `curl -u user:password`: the part after the colon, and only when there is one (`curl -u user` asks for it)
    ("a password given to curl", re.compile(
        r"""(?i:(?<![\w.-])curl(?:\.exe)?(?=\s))(?:(?!(?i:curl)\b)[^\n]){0,512}?(?<=\s)(?:-u|-U|--user|--proxy-user)(?:\s+|=)(?:"[^":\n]*:([^"\n]{1,256})"|'[^':\n]*:([^'\n]{1,256})'|[^\s:"']*:([^\s"']{1,256}))"""), -3),
    ("a hash pair of an account database", re.compile(r"(?<![0-9a-fA-F])[0-9a-fA-F]{32}:([0-9a-fA-F]{32})(?![0-9a-fA-F])"), 1),
    ("a bcrypt hash", re.compile(r"(?<![A-Za-z0-9$])\$2[abxy]?\$[0-9]{2}\$[./A-Za-z0-9]{53}(?![./A-Za-z0-9])"), 0),
    ("a token of a known family", re.compile(
        r"(?:GOCSPX-[A-Za-z0-9_-]{20,}|gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{50,}|xox[abprs]-[A-Za-z0-9-]{10,}|AIza[0-9A-Za-z_-]{35}(?![0-9A-Za-z_-])|"
        r"ya29\.[0-9A-Za-z_-]{20,}|1//0[0-9A-Za-z_-]{30,}|(?:IQoJb3JpZ2lu|FQoGZXIvYXdz|FwoGZXIvYXdz)[A-Za-z0-9+/=]{40,}|"
        r"[A-Za-z0-9_.~-]{3}[0-9]Q~[A-Za-z0-9_.~-]{30,}|[01]\.A[A-Za-z0-9_-]{50,}|[sr]k_(?:live|test)_[A-Za-z0-9]{16,})"), 0),
]
_CRED_GROUPS = {-1: (1, 2, 3), -2: (1, 2), -3: (1, 2, 3)}
# A random-looking run of an exact length that keys have: 32, 40 (an AWS secret access key), 43 + "=" and 86 + "==" (a base64 key).
_CRED_SHAPES = [
    ("a key-length base64 string", re.compile(_CRED_B64_EDGE + r"(?:[A-Za-z0-9+/]{32}|[A-Za-z0-9+/]{40}|[A-Za-z0-9+/]{43}=|[A-Za-z0-9+/]{86}==)" + _CRED_B64_END), True),
]
# A Name/Value pair written as JSON text inside a string (an AuditData in a column of another name, a parameter list in a cell): the
# structure rule (clean_value) cannot see it, so the text rule reads the head of the pair, and the name decides as it does there. The
# value is read by hand, not by an expression: a string up to its first quote (the backslashes before the quote are not part of it), a
# number, a flat array of up to 4,096 characters, or a literal; and the next value of the same pair (`OldValue`, then `NewValue`).
_CRED_PAIR_HEAD = re.compile(r"""(?i)\b(?:name|key)\\*"\s*:\s*\\*"([^"\\]{1,64})\\*"\s*,\s*\\*"(?:new|old)?value\\*"\s*:\s*""")
_CRED_NEXT_VALUE = re.compile(r"""(?i)\s*,\s*\\*"(?:new|old)?value\\*"\s*:\s*""")
_CRED_QUOTE = re.compile(r'\\*"')
# a format directive (`%s`, `%d`), a template field (`{0}`, `{name}`) or a `%VAR%` is where a value goes, not a value
_CRED_PLACEHOLDER = re.compile(r"%[-+ #0-9.]*[sdiuxXfeEgGcr](?![A-Za-z0-9])|\{\w*\}|%\w+%$|\.{2,}|\u2026")
_CRED_BARE = re.compile(r"-?[0-9][0-9.eE+-]{0,39}|\[[^\[\]]{0,4096}\]|(?:null|true|false)\b")
# What a text must hold for a rule to match it: a literal (lower case) of which one must be in the text, checked before the rule runs, so
# that a text with none of them (most names, addresses and ids) costs a few substring tests and no expression. An assignment rule also
# needs a separator in the text. Each is a necessary condition of its rule.
_CRED_ASSIGN = ("pass", "pwd", "secret", "key", "token", "signature", "plaintext", "sig", "pin", "otp", "sas", "hash")
_CRED_NEEDLES = {
    "a JSON Web Token": ("eyj",), "a JSON Web Encryption token": ("eyj",), "a password in a URL": ("://",),
    "an Azure Functions key": ("x-functions-key", "code="), "a private key block": ("-----begin",), "a base64 block of key lines": ("\n",),
    "an authorization header value": ("authorization",), "a cookie header value": ("cookie",),
    "a scheme and its credential": ("bearer", "basic", "negotiate", "ntlm", "digest"),
    "a value assigned to a credential name (quoted)": _CRED_ASSIGN, "a value assigned to a credential name": _CRED_ASSIGN,
    "a value given to a credential switch": ("password", "pass", "pwd", "secret", "apikey", "accesstoken", "token"),
    "a secret given to ConvertTo-SecureString": ("securestring",), "a password given to a MySQL client": ("mysql", "mariadb"),
    "a password given to curl": ("curl",), "a hash pair of an account database": (":",), "a bcrypt hash": ("$2",),
    "a token of a known family": ("gocspx-", "ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_", "xoxa-", "xoxb-", "xoxp-", "xoxr-", "xoxs-",
                                  "aiza", "ya29.", "1//0", "iqojb3", "fqogzx", "fwogzx", "q~", "0.a", "1.a", "sk_", "rk_"),
}
_CRED_CLEAN = set()               # short texts already judged to hold nothing (names, addresses and ids repeat)
_CRED_GATE = 4096                 # a text longer than this is scanned with the carrier's hook in view, rule by rule
# The carrier's hook for long scans: called with the work done so far (1 per stretch found, 4096 between rules over a long text); it may
# raise to end the scan at the carrier's deadline. Most carriers set none and the calls do nothing.
_tick = globals().get("WITHHOLD_TICK") or (lambda units=1: None)


def _cred_json_value(text, at):
    """(start, end, after) of the JSON value whose text starts at `at`: `end` is where what is withheld ends, `after` where the next
    token of the pair begins. None when no value starts there."""
    q = _CRED_QUOTE.match(text, at)
    if q:
        start = q.end()
        close = text.find('"', start)
        if close < 0:
            return start, len(text), len(text)      # a value that is cut off: the rest of the text is the value
        return start, start + len(text[start:close].rstrip("\\")), close + 1
    m = _CRED_BARE.match(text, at)
    if m is None:
        return None
    if m.group()[0] in "nft":
        return at, at, m.end()                     # null, true and false are not secrets
    return m.start(), m.end(), m.end()


def _cred_pair_spans(text, spans):
    for head in _CRED_PAIR_HEAD.finditer(text):
        if not name_is_sensitive(head.group(1)):
            continue
        at = head.end()
        for _ in range(3):
            got = _cred_json_value(text, at)
            if got is None:
                break
            start, end, after = got
            if end > start:
                value = text[start:end]
                if not (_CRED_REDACTED.match(value) or value.lower() in _CRED_NOT_A_VALUE or value.startswith(("${", "{{")) or _CRED_PLACEHOLDER.match(value)):
                    spans.append((start, end, _CRED_PAIR_WHY))
            more = _CRED_NEXT_VALUE.match(text, after)
            if more is None:
                break
            at = more.end()


def _cred_random_like(run):
    """A run that looks like random base64 and not like a path, a name or a hash: mixed case and digits in the proportions
    random text has (a long path is mostly lower case with few capitals; a hex digest has no case to mix)."""
    n = len(run)
    upper = sum(1 for ch in run if "A" <= ch <= "Z")
    lower = sum(1 for ch in run if "a" <= ch <= "z")
    digit = sum(1 for ch in run if "0" <= ch <= "9")
    return upper * 100 >= 15 * n and lower * 100 >= 15 * n and digit * 100 >= 5 * n


def _cred_name_before(text, at):
    """The letters and digits of the name an assigned value follows (`nextToken=` gives `nexttoken`)."""
    return re.sub(r"[^a-z0-9]", "", text[max(0, at - 64):at].lower())


def _cred_spans(text, shapes, skip=()):
    spans = []
    big = len(text) > _CRED_GATE
    low = text.lower()
    sep = "=" in text or ":" in text or "%3" in low
    if "value" in low:
        _cred_pair_spans(text, spans)
    for why, rx, group in _CRED_RULES:
        if why in skip:
            continue
        need = _CRED_NEEDLES[why]
        if need is _CRED_ASSIGN and not sep:
            continue
        for n in need:
            if n in low:
                break
        else:
            continue
        if big:
            _tick(4096)
        for m in rx.finditer(text):
            if big:
                _tick(1)
            if "assigned to a credential name" in why:
                if _CRED_ARN_TAIL.search(text[max(0, m.start() - 120):m.start()]):
                    continue                              # arn:aws:secretsmanager:...:secret:NAME is a name, not a value
                if _cred_name_before(text, m.start(m.lastindex or 0)).endswith(_CRED_NOT_SECRET):
                    continue                              # nextToken=, pageToken=, clientToken=: a position or an idempotency key
            for g in _CRED_GROUPS.get(group, (group,)):
                if g and m.group(g) is None:
                    continue
                start, end = m.span(g)
                value = text[start:end]
                if g and (_CRED_REDACTED.match(value) or value.lower() in _CRED_NOT_A_VALUE or value.startswith(("${", "{{")) or _CRED_PLACEHOLDER.match(value)):
                    continue
                if why == "a scheme and its credential" and g == 1 and not (re.search(r"[0-9+/=_.~-]", value) or len(value) >= 16):
                    continue                              # "basic authentication" is prose, "Basic dXNlcjpwYXNz" is not
                if g == 1 and group == -1 and len(m.groups()) >= 2 and m.group(1) in ("'", '"'):
                    continue                              # group 1 of the switch rules is the quote
                spans.append((start, end, why))
    if big:
        _tick(4096)
    for m in (_CRED_B64_RUN.finditer(text) if len(text) >= 128 and "a long unbroken base64-like run" not in skip else ()):
        if _cred_random_like(m.group(0)):
            spans.append((m.start(), m.end(), "a long unbroken base64-like run"))
    if shapes and len(text) >= 32 and "a key-length base64 string" not in skip:
        for why, rx, check in _CRED_SHAPES:
            for m in rx.finditer(text):
                if not check or _cred_random_like(m.group(0)):
                    spans.append((m.start(), m.end(), why))
    spans.sort()
    merged = []
    for s in spans:
        if merged and s[0] < merged[-1][1]:
            if s[1] > merged[-1][1]:
                merged[-1] = (merged[-1][0], s[1], merged[-1][2])
            continue
        merged.append(s)
    return merged


def credential_spans(text, shapes=True, skip=()):
    """(start, end, why) of each stretch of `text` that is a credential by the name it is given under or by its text, in order and
    not overlapping. `shapes` False leaves out the rules that recognise a key by its length alone (a value that is named a checksum or
    a digest is not scanned for them). This is not `token_spans`: an identifier (a GUID, a hex digest, an access key id, an ARN) is
    not a credential here, and a tool that prints identifiers on purpose asks only for these."""
    if len(text) > TEXT_LIMIT:
        return [(0, len(text), "text longer than %d characters" % TEXT_LIMIT)]
    if shapes and not skip and text in _CRED_CLEAN:
        return []
    spans = _cred_spans(text, shapes, skip)
    if shapes and not skip and not spans and len(text) <= 256 and len(_CRED_CLEAN) < 100000:
        _CRED_CLEAN.add(text)
    return spans


def clean_value(value, leaf, note, key=None, pointer="", depth=0, shapes=True, max_depth=200):
    """The structure rule: `value` (what a JSON document decoded to) with every credential in it replaced. A string goes to
    `leaf(text, pointer, shapes)`, which returns what is printed for it. A field whose name says it holds a secret (or a `Value` whose
    `Name` does), at any depth, is not read at all: `note(pointer, why, original)` returns what is printed for it (a number under such
    a name is withheld too: 0 and 1 are not nothing). A key goes through `key(text)` when one is given. A value nested deeper than
    `max_depth` is replaced the same way."""
    if isinstance(value, str):
        return leaf(value, pointer, shapes)
    _tick(1)
    if depth > max_depth and isinstance(value, (dict, list)):
        return note(pointer, "nested deeper than %d levels" % max_depth, value)
    if isinstance(value, dict):
        named = None
        for k in _CRED_NAME_KEYS:
            if isinstance(value.get(k), str):
                named = value[k]
                break
        pair_secret = named is not None and name_is_sensitive(named)
        out = {}
        for k, v in value.items():
            ks = str(k)
            point = "%s/%s" % (pointer, ks.replace("~", "~0").replace("/", "~1"))
            safe_key = key(ks) if key is not None else ks
            if safe_key in out:
                safe_key = "%s#%d" % (safe_key, len(out))
            sensitive = name_is_sensitive(ks) or (pair_secret and ks in _CRED_VALUE_KEYS)
            if sensitive and is_container_name(ks) and isinstance(v, (dict, list)):
                sensitive = False
            if sensitive and not (v is None or isinstance(v, bool) or v == "") and not (isinstance(v, str) and (_CRED_REDACTED.match(v) or v.lower() in _CRED_NOT_A_VALUE)):
                out[safe_key] = note(point, "credential-named field", v)
            else:
                out[safe_key] = clean_value(v, leaf, note, key, point, depth + 1, shapes and not _CRED_CHECKSUM_NAME.search(ks), max_depth)
        return out
    if isinstance(value, list):
        return [clean_value(v, leaf, note, key, "%s/%d" % (pointer, i), depth + 1, shapes, max_depth) for i, v in enumerate(value)]
    return value


# what the rules of the block above already withhold whole, with their own markers: the first pass leaves these to them
_CRED_OLD_COVERS = frozenset(("a JSON Web Token", "a password in a URL", "an authorization header value", "a scheme and its credential",
                              "a long unbroken base64-like run", "a key-length base64 string"))


def _credentials_withheld(text, kind, skip=()):
    """`text` with each credential in it withheld. It runs after the rules above, on text that may hold their markers: a stretch that
    begins at a marker is theirs already."""
    out, last = [], 0
    for start, end, why in credential_spans(text, True, skip):
        if text.startswith("<", start):
            continue
        out.append(text[last:start])
        out.append(_withheld(why, end - start, kind))
        last = end
    if not out:
        return text
    out.append(text[last:])
    return "".join(out)


def scrub(text, kind="text"):
    """The text with every token-shaped run, every user-info and every credential withheld."""
    if len(text) > TEXT_LIMIT:
        return _withheld("over-long text", len(text), kind)
    text = _credentials_withheld(text, kind, _CRED_OLD_COVERS)     # first: the rules above cut a secret into pieces that no rule for a whole one can match
    text = _USERINFO.sub(lambda m: _withheld("userinfo", len(m.group()), kind), text)
    text = _BARE_USERINFO.sub(lambda m: _withheld("userinfo", len(m.group()), kind), text)
    out, last = [], 0
    for start, end in token_spans(text):
        out.append(text[last:start])
        out.append(_withheld("token-shaped text", end - start, kind))
        last = end
    out.append(text[last:])
    return _credentials_withheld("".join(out), kind)


def redact_url(url):
    """A URL or request target without its user-info, its token-shaped path text, its query values or its fragment."""
    rest, fragment = (url.split("#", 1) + [None])[:2]
    rest, query = (rest.split("?", 1) + [None])[:2]
    scheme = authority = ""
    m = re.match(r"^((?:[A-Za-z][A-Za-z0-9+.-]*:)?//)([^/]*)(.*)$", rest, re.S)
    if m:
        scheme, authority, rest = m.group(1), m.group(2), m.group(3)
        if "@" in authority:
            userinfo, authority = authority.rsplit("@", 1)
            authority = _withheld("userinfo", len(userinfo), "urls") + "@" + authority
    out = scheme + authority + scrub(rest, "urls")
    if query is not None:
        pairs = []
        for pair in query.split("&"):
            name, eq, value = pair.partition("=")
            pairs.append(scrub(name, "urls") + (eq + _withheld("", len(value), "urls") if eq else ""))
        out += "?" + "&".join(pairs)
    if fragment is not None:
        out += "#" + _withheld("", len(fragment), "urls")
    return out


def cell(value):
    """Text for one tab-separated cell or one printed path: no tab or line break, and a byte that was not UTF-8
    (a lone surrogate) written as \\xNN, so that no writer raises on it."""
    text = value if isinstance(value, str) else str(value)
    out = []
    for ch in text:
        o = ord(ch)
        if ch == "\\":
            out.append("\\\\")
        elif ch == "\t":
            out.append("\\t")
        elif ch == "\r":
            out.append("\\r")
        elif ch == "\n":
            out.append("\\n")
        elif 0xDC80 <= o <= 0xDCFF:
            out.append("\\x%02x" % (o - 0xDC00))
        elif 0xD800 <= o <= 0xDFFF:
            out.append("\\u%04x" % o)
        elif o < 0x20 or o == 0x7F:
            out.append("\\x%02x" % o)
        else:
            out.append(ch)
    return "".join(out)
# END SHARED WITHHOLDING

# What a statement may do. SELECT and READ are reading; FUNCTION is a call to a
# built-in; RECURSIVE is a recursive CTE. Everything else is refused, whatever
# the open mode would have said.
ALLOWED_ACTIONS = {sqlite3.SQLITE_SELECT, sqlite3.SQLITE_READ, sqlite3.SQLITE_FUNCTION,
                   getattr(sqlite3, "SQLITE_RECURSIVE", 33)}
DENIED_FUNCTIONS = {"load_extension", "fts3_tokenizer", "readfile", "writefile", "edit"}
# Pragmas that only report. A setter form (an argument) is refused for all but those
# that take a table name as their argument.
READ_PRAGMAS = {"table_info", "table_xinfo", "table_list", "index_list", "index_info", "index_xinfo",
                "foreign_key_list", "foreign_key_check", "database_list", "collation_list", "function_list",
                "module_list", "pragma_list", "compile_options", "page_size", "page_count", "freelist_count",
                "user_version", "application_id", "schema_version", "encoding", "journal_mode", "integrity_check",
                "quick_check", "data_version", "max_page_count", "auto_vacuum", "wal_autocheckpoint", "cache_size"}
PRAGMAS_WITH_NAME = {"table_info", "table_xinfo", "index_list", "index_info", "index_xinfo", "foreign_key_list",
                     "foreign_key_check", "integrity_check", "quick_check"}
LEADING = ("select", "with", "values", "pragma", "explain")


VALUES_MODE = [False]
# What a values-mode answer prints about the evidence's own names (the file, the table, the columns, a message quoting them)
# goes through the shared block's scrub, so a name shaped like a token is withheld on every channel. A digest of the file is
# the file's identity and stays whole.
SCRUBBED_KEYS = ("error", "stderr", "db_path", "database_opened", "table", "column", "reason", "statement")


def scrub_answer(obj):
    out = dict(obj)
    for key in SCRUBBED_KEYS:
        if isinstance(out.get(key), str):
            out[key] = scrub(out[key])
    snap = out.get("snapshot")
    if isinstance(snap, dict):
        out["snapshot"] = {k: (scrub(v) if k in ("source", "receipt") and isinstance(v, str) else v) for k, v in snap.items()}
    return out


def answer_status(obj):
    """`status` (complete, partial or failed) and a one-sentence `status_basis` for an answer that has none (docs/packs.md, "The
    tool contract"). `ok` and `complete` keep their meaning. The sentence is fixed text: it names keys of the answer, never a
    value or a name from the evidence, so it is as safe in values mode as anywhere."""
    if "status" in obj and "status_basis" in obj:
        return obj
    out = dict(obj)
    values = out.get("mode") == "values_to_file"
    if out.get("ok") is False:
        if out.get("timed_out") or out.get("values_file_error"):
            out["status"] = "partial"
            out["status_basis"] = ("the read stopped at its time budget (timed_out), so what was read before the stop is kept and named (%s) "
                                   "and the rest of the result was not read" % ("the values file and rows_read_before_the_stop" if values else "rows_read_before_the_stop")
                                   if out.get("timed_out") else
                                   "the values file could not be written to the end (values_file_error): values_file_holds and values_file_state say how far it got")
        else:
            out["status"] = "failed"
            out["status_basis"] = "the tool stopped with an error or a refusal and returned no result of the request (see error)"
        return out
    if out.get("complete") is False:
        why = []
        if out.get("values_file_stopped_at_row"):
            why.append("the values file stopped at its size cap (values_file_stopped_at_row, resume)")
        if out.get("cells_not_exported"):
            why.append("some cells were not exported (cells_not_exported)")
        if out.get("locators_file_error"):
            why.append("the locators file could not be written (locators_file_error)")
        if out.get("locators_file_stopped_at_row"):
            why.append("the locators file stopped at its size cap (locators_file_stopped_at_row)")
        if out.get("rows_file_error") or out.get("rows_file_stopped_at_row"):
            why.append("the file that should hold every row could not be written to the end (rows_file_error or rows_file_stopped_at_row)")
        out["status"] = "partial"
        out["status_basis"] = ("the request ran but not all of its result was delivered: " + "; ".join(why)) if why else \
            "the request ran but not all of its result was delivered (complete is false)"
        return out
    out["status"] = "complete"
    if values:
        out["status_basis"] = ("every row of the table's range was read and exported to the values file, and the locators file holds every row "
                               "(row_count, secret_values and locators_file say how many)")
    elif out.get("truncated"):
        out["status_basis"] = ("every statement ran to its end; the inline page holds the first rows and the file rows_file names holds every "
                               "row (row_count counts them all)")
    else:
        out["status_basis"] = "every statement ran to its end and every row of the result is in this answer (row_count counts them)"
    return out


def say(obj, code=0):
    if VALUES_MODE[0]:
        obj = scrub_answer(obj)
    print_answer(answer_status(obj))
    raise SystemExit(code)


def authorizer(action, p1, p2, dbname, source):
    if action in ALLOWED_ACTIONS:
        if action == sqlite3.SQLITE_FUNCTION and (p2 or "").lower() in DENIED_FUNCTIONS:
            return sqlite3.SQLITE_DENY
        return sqlite3.SQLITE_OK
    if action == sqlite3.SQLITE_PRAGMA:
        name = (p1 or "").lower()
        if name in READ_PRAGMAS and (p2 is None or name in PRAGMAS_WITH_NAME):
            return sqlite3.SQLITE_OK
    return sqlite3.SQLITE_DENY


def statements(sql):
    """The statements of `sql`, split where sqlite says one is complete (a ';' inside
    a string or a trigger body does not end it). What follows the last ';' is a statement too,
    complete or not: a line comment at its end does not hide it, and an incomplete one (an
    unterminated string, a trigger with no END) is handed to sqlite to refuse, never dropped."""
    out, start = [], 0
    for i, ch in enumerate(sql):
        if ch == ";" and sqlite3.complete_statement(sql[start:i + 1]):
            out.append(sql[start:i + 1])
            start = i + 1
    out.append(sql[start:])
    return [s.strip() for s in out if re.sub(r"(--[^\n]*\n?|/\*.*?\*/|\s|;)+", "", s, flags=re.S)]


def first_word(stmt):
    stripped = re.sub(r"^(\s|--[^\n]*\n|/\*.*?\*/)+", "", stmt, flags=re.S)
    m = re.match(r"[A-Za-z]+", stripped)
    return m.group(0).lower() if m else ""


def entropy(page):
    counts = collections.Counter(page)
    return -sum(c / len(page) * math.log2(c / len(page)) for c in counts.values())


def sha256_file(path):
    h = hashlib.sha256()
    with open_regular(path) as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def wal_inventory(path):
    """What the WAL file says about itself, from its header and its frame headers:
    the frames that belong to its current generation (their salts match the header's)
    and the last commit among them. Checksums are not verified."""
    size = os.path.getsize(path)
    info = {"bytes": size}
    if size < 32:
        info["state"] = "empty or shorter than its 32-byte header"
        info["frames_valid"] = 0
        return info
    with open_regular(path) as fh:
        head = fh.read(32)
        magic, version, page, seq, salt1, salt2 = struct.unpack(">IIIIII", head[:24])
        if magic not in (0x377F0682, 0x377F0683) or not 512 <= page <= 65536 or page & (page - 1):
            info["state"] = "not a WAL header (magic %08x, page size %d)" % (magic, page)
            info["frames_valid"] = 0
            return info
        stride = 24 + page
        total = (size - 32) // stride
        valid, last_commit = 0, 0
        for i in range(total):
            fh.seek(32 + i * stride)
            fr = fh.read(24)
            if len(fr) < 24:
                break
            pgno, commit, s1, s2 = struct.unpack(">IIII", fr[:16])
            if s1 != salt1 or s2 != salt2 or pgno == 0:
                break
            valid += 1
            if commit:
                last_commit = valid
    info.update({"page_size": page, "checkpoint_sequence": seq, "frames_in_file": total, "frames_valid": valid,
                 "frames_committed": last_commit, "state": "frames of the current generation counted from their salts; checksums not verified"})
    return info


JOURNAL_MAGIC = bytes([0xD9, 0xD5, 0x05, 0xF9, 0x20, 0xA1, 0x63, 0xD7])


def journal_inventory(path):
    """A rollback journal is hot only when its header is the journal's: a header of zeros (what journal_mode
    TRUNCATE and PERSIST leave) means there is nothing to roll back."""
    with open_regular(path) as fh:
        head = fh.read(28)
    if head[:8] == JOURNAL_MAGIC:
        return {"state": "header present: a journal that was not rolled back"}
    if not head.strip(b"\0"):
        return {"state": "empty or zeroed header: not a hot journal (a persistent or truncated one left behind)"}
    return {"state": "a header that is not a rollback journal's; not applied, not understood"}


def sidecars(db):
    """The files beside the database, named from its real path: SQLite looks for a -wal and a -journal next to the
    file a link points at, not next to the link."""
    real = os.path.realpath(db)
    out = []
    for suffix in ("-wal", "-shm", "-journal"):
        path = real + suffix
        entry = {"name": os.path.basename(path), "present": os.path.isfile(path)}
        if entry["present"]:
            try:
                entry["bytes"] = os.path.getsize(path)
                if suffix == "-wal":
                    entry.update(wal_inventory(path))
                if suffix == "-journal" and entry["bytes"]:
                    entry.update(journal_inventory(path))
                if entry["bytes"] <= HASH_MAX:
                    entry["sha256"] = sha256_file(path)
            except OSError as exc:
                entry["error"] = exc.strerror or str(exc)
        out.append(entry)
    return out


RECEIPT_MAX = 16 * 1024 * 1024


def read_receipt(path):
    try:
        if os.path.getsize(path) > RECEIPT_MAX:
            return None
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        return None
    tool = data.get("tool") if isinstance(data, dict) else None
    return data if isinstance(tool, dict) and tool.get("name") == "sqlite_snapshot" else None


def find_snapshot(db):
    """(path of the database to open, snapshot facts or None). `db` may be a sqlite_snapshot directory, or the database inside one
    (<snapshot>/original/database.sqlite or <snapshot>/applied/database.sqlite); anything else is an ordinary file."""
    if os.path.isdir(db):
        receipt = read_receipt(os.path.join(db, "snapshot.json"))
        if receipt is None:
            return db, None
        root = db
        target = os.path.join(root, receipt.get("database") or "")
    else:
        parent = os.path.dirname(os.path.abspath(db))
        root = os.path.dirname(parent)
        receipt = read_receipt(os.path.join(root, "snapshot.json")) if os.path.basename(parent) in ("original", "applied") else None
        if receipt is None:
            return db, None
        target = db
    rel = os.path.relpath(os.path.abspath(target), os.path.abspath(root))
    applied = receipt.get("applied") or {}
    wal = receipt.get("wal") or {}
    which = rel.split(os.sep)[0]
    recorded = applied.get("sha256") if which == "applied" else (receipt.get("source") or {}).get("sha256")
    facts = {
        "receipt": os.path.join(root, "snapshot.json"), "queried": rel, "queried_is": ("the copy with the WAL applied" if which == "applied" else "the copy of the main file as it was"),
        "source": (receipt.get("source") or {}).get("db_path"), "source_sha256": (receipt.get("source") or {}).get("sha256"),
        "wal_applied": bool(receipt.get("wal_applied")), "wal_frames_committed": wal.get("frames_committed"), "wal_frames_valid": wal.get("frames_valid"),
        "wal_frames_uncommitted_valid": wal.get("frames_uncommitted_valid"), "snapshot_status": receipt.get("status"),
        "snapshot_problems": receipt.get("problems") or [], "snapshot_notes": receipt.get("notes") or [], "recorded_sha256": recorded,
        "rollback_journal": (receipt.get("rollback_journal") or {}).get("state"),
    }
    return target, facts


def snapshot_note(facts, side):
    """What state of the source this snapshot's database is, in words; the plain sidecar report would be wrong inside a snapshot."""
    notes = []
    if facts["queried"].startswith("applied"):
        notes.append("SNAPSHOT: this is the copy of %s with its WAL applied by SQLite (%s committed frame(s)); the originals were not touched." % (
            facts["source"] or "the source", facts["wal_frames_committed"]))
        if facts["wal_frames_uncommitted_valid"]:
            notes.append("%d valid WAL frame(s) after the last commit were not applied." % facts["wal_frames_uncommitted_valid"])
    else:
        notes.append("SNAPSHOT: this is the snapshot's copy of the main file as it was%s." % (
            "; its WAL is NOT applied here (the applied copy is applied/database.sqlite)" if facts["wal_frames_committed"] else ""))
    if facts["rollback_journal"] and facts["rollback_journal"].startswith("header present"):
        notes.append("A hot rollback journal was beside the source and was not rolled back: the main file may hold an interrupted write.")
    if facts["snapshot_status"] != "complete":
        notes.append("The snapshot itself is %s: %s" % (facts["snapshot_status"], "; ".join(facts["snapshot_problems"][:3]) or "see its receipt"))
    return " ".join(notes)


def snapshot_status(side):
    """Said plainly: what state of the database this result is."""
    notes = []
    wal = next((s for s in side if s["name"].endswith("-wal") and s.get("present")), None)
    jrn = next((s for s in side if s["name"].endswith("-journal") and s.get("present")), None)
    if wal and wal.get("frames_valid"):
        notes.append("WAL NOT APPLIED: the main file was read immutable, so the %d frame(s) (%d committed) in %s are not in this result; "
                     "a row committed only there is missing. To read that state, run sqlite_snapshot on the database (it copies the set, hashed, and "
                     "has SQLite apply the WAL in the copy) and query the `database` it names." % (wal["frames_valid"], wal.get("frames_committed", 0), wal["name"]))
    elif wal and wal.get("bytes"):
        notes.append("%s is present (%d bytes) and holds no valid frame; the main file is the whole database state this tool can read." % (wal["name"], wal["bytes"]))
    if jrn and jrn.get("bytes") and jrn.get("state", "").startswith("header present"):
        notes.append("%s is present (%d bytes): a rollback journal that was not rolled back; the main file may hold an interrupted write. Not applied." % (jrn["name"], jrn["bytes"]))
    elif jrn and jrn.get("bytes"):
        notes.append("%s is present (%d bytes): %s." % (jrn["name"], jrn["bytes"], jrn.get("state", "its header was not read")))
    if not notes:
        return "main file only; no WAL frames or hot journal beside it"
    return " ".join(notes)


def typed_cell(value):
    """A typed JSON value for a cell: null, number, string, or an object that keeps what a string cannot."""
    if value is None or isinstance(value, (int, float)):
        if isinstance(value, float) and (math.isnan(value) or math.isinf(value)):
            return {"real": repr(value)}
        return value
    if isinstance(value, bytes):
        return {"blob_b64": base64.b64encode(value).decode("ascii"), "length": len(value), "sha256": hashlib.sha256(value).hexdigest()}
    if isinstance(value, _Text):
        return {"text_invalid_utf8": str(value), "bytes_b64": base64.b64encode(value.raw).decode("ascii"), "length": len(value.raw)}
    return value


class _Text(str):
    """Text from the database that was not valid UTF-8, kept with its bytes."""
    raw = b""


def text_factory(raw):
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        t = _Text(raw.decode("utf-8", "backslashreplace"))
        t.raw = bytes(raw)
        return t


def inline_cell(value):
    """The same, with a long BLOB shown by its head: the file holds it whole."""
    c = typed_cell(value)
    if isinstance(c, dict) and "blob_b64" in c and c["length"] > BLOB_INLINE:
        return {"blob_b64_head": base64.b64encode(value[:BLOB_INLINE]).decode("ascii"), "length": c["length"], "sha256": c["sha256"],
                "head_bytes": BLOB_INLINE}
    return c


def text_cell(value, csv_mode):
    if value is None:
        return ""
    if isinstance(value, bytes):
        return "<blob %d bytes>" % len(value)
    if isinstance(value, float):
        return "%.15g" % value
    return str(value)


def blob_json(fh, value):
    """A BLOB as {blob_b64, length, sha256}, written to `fh` in slices: the digest is taken first over views of the value,
    then the base64 is written slice by slice, so a large value costs no second copy of itself in memory."""
    digest = hashlib.sha256()
    view = memoryview(value)
    for at in range(0, len(view), SLICE_BYTES):
        digest.update(view[at:at + SLICE_BYTES])
    fh.write('{"blob_b64": "')
    for at in range(0, len(view), SLICE_BYTES):
        fh.write(base64.b64encode(view[at:at + SLICE_BYTES]).decode("ascii"))
    fh.write('", "length": %d, "sha256": "%s"}' % (len(value), digest.hexdigest()))


def earlier_answers(path):
    """How many other files answer this same question in the folder (name.ext, name.2.ext, ...): one more for every different
    answer, and none is deleted, so the count is said."""
    stem, ext = os.path.splitext(os.path.basename(str(path)))
    base = re.sub(r"\.\d+$", "", stem)
    rx = re.compile(r"^%s(\.\d+)?%s$" % (re.escape(base), re.escape(ext)))
    try:
        return max(0, sum(1 for n in os.listdir(os.path.dirname(str(path)) or ".") if rx.match(n)) - 1)
    except OSError:
        return 0


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


def publish(tmp, path, shown, left=None):
    result = _publish(tmp, path, shown, left)
    temp_done(tmp)                                        # it is in place (a link, a rename) or gone: no longer a temporary
    return result


def _publish(tmp, path, shown, left=None):
    """Move a finished file to `path` without replacing what is there: a file at the name is an earlier answer (a complete one,
    perhaps, where this run was cut short) and stays; this one is kept beside it as name.2.ext. Returns the name it has and
    the name to show for it. With a list `left`, a temporary name that cannot be removed once the file is in place is added to
    it instead of raising (the file is published; the caller says what remains)."""
    stem, ext = os.path.splitext(str(path))
    shown_stem, _ = os.path.splitext(shown)

    def drop_tmp():
        try:
            os.unlink(tmp)
        except OSError:
            if left is None:
                raise
            left.append(tmp)
    k = 1
    while True:
        suffix = "" if k == 1 else ".%d" % k
        candidate = Path(stem + suffix + ext)
        try:
            os.link(tmp, candidate)
        except FileExistsError:
            if same_bytes(tmp, candidate):                # the same answer again (a page of the same search): the file is already there
                drop_tmp()
                return candidate, shown_stem + suffix + ext
            k += 1
            continue
        except OSError:                                   # a file system with no hard links: a look, then a rename
            if os.path.lexists(candidate):
                if same_bytes(tmp, candidate):
                    drop_tmp()
                    return candidate, shown_stem + suffix + ext
                k += 1
                continue
            os.rename(tmp, candidate)
            return candidate, shown_stem + suffix + ext
        drop_tmp()
        return candidate, shown_stem + suffix + ext


def raw_size(row):
    return sum(len(v) if isinstance(v, (bytes, str)) else 8 for v in row)


class Rows:
    """One statement's rows: an inline page, and the whole result in a file once it is more than that.

    The inline page is bounded by what is sent (its JSON and its text form, as bytes), by `limit`, and by
    the raw values held to make it (RAW_BUFFER_MAX): a row too large to hold goes to the file only."""

    def __init__(self, stmt_index, key, columns, limit):
        self.limit, self.columns = limit, columns
        self.page, self.raw_page, self.inline_bytes, self.raw_bytes = [], [], 0, 0
        self.total, self.fh, self.tmp, self.written = 0, None, None, 0
        PAGES.append(self)
        self.file_stopped = None
        digest = hashlib.sha256(json.dumps(key, sort_keys=True, default=str).encode()).hexdigest()[:16]
        name = "sqlite_query-%s-%d.jsonl" % (digest, stmt_index)
        job, out = os.environ.get("JOB_ID"), os.environ.get("OUT")
        if job and out:
            self.path = Path(out) / "tool-output" / name
            self.shown = "store/jobs/%s/out/tool-output/%s" % (re.sub(r"[^A-Za-z0-9_.-]", "_", job), name)
        else:
            agent = re.sub(r"[^A-Za-z0-9_.-]", "_", os.environ.get("AGENT_ID") or "tool")
            self.path = Path("work") / agent / "tool-output" / name
            self.shown = str(self.path)
        self.error = None

    def _open(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd, name = temp_create(self.path.parent, ".sqlite_query-")
        self.tmp = Path(name)
        try:
            self.fh = os.fdopen(fd, "w", encoding="utf-8")
        except BaseException:
            os.close(fd)
            raise
        self.fh.write(json.dumps({"columns": self.columns}) + "\n")
        for n, row in enumerate(self.raw_page, 1):
            self._write(n, row)

    def _write(self, n, row):
        if self.file_stopped:
            return
        big = any(isinstance(v, bytes) and len(v) > STREAM_AT for v in row)
        if not big:
            line = json.dumps({"n": n, "values": [typed_cell(v) for v in row]}, ensure_ascii=False) + "\n"
            if self.written + len(line) > FILE_BYTES:
                self.file_stopped = n
                return
            self.fh.write(line)
            self.written += len(line)
            return
        # A row with a large BLOB: its size is known before it is written, and the BLOB is encoded in slices.
        size = sum(4 * ((len(v) + 2) // 3) + 120 if isinstance(v, bytes) else len(json.dumps(typed_cell(v), ensure_ascii=False)) + 2 for v in row) + 40
        if self.written + size > FILE_BYTES:
            self.file_stopped = n
            return
        self.fh.write('{"n": %d, "values": [' % n)
        for i, v in enumerate(row):
            if i:
                self.fh.write(", ")
            if isinstance(v, bytes) and len(v) > STREAM_AT:
                blob_json(self.fh, v)
            else:
                self.fh.write(json.dumps(typed_cell(v), ensure_ascii=False))
        self.fh.write("]}\n")
        self.written += size

    def _drop_file(self, exc):
        """The whole-result file cannot be written (a full disk, a read-only directory): said, and no half file left."""
        self.error = "the whole result could not be written (%s): %s" % (self.path.parent, getattr(exc, "strerror", None) or exc)
        try:
            if self.fh:
                self.fh.close()
        except (OSError, ValueError):
            pass
        self.fh = False
        if self.tmp:
            try:
                self.tmp.unlink()
            except OSError:
                pass
            self.tmp = None

    def add(self, row):
        self.total += 1
        if self.fh is None:
            size = raw_size(row)
            if len(self.page) < self.limit and size <= INLINE_BYTES and self.raw_bytes + size <= RAW_BUFFER_MAX:
                inline = [inline_cell(v) for v in row]
                sent = len(json.dumps({"n": self.total, "values": inline}).encode("utf-8"))
                text = len(json.dumps("|".join(text_cell(v, False) for v in row)).encode("utf-8"))
                if self.inline_bytes + sent + text <= 2 * INLINE_BYTES:
                    self.page.append({"n": self.total, "values": inline})
                    self.raw_page.append(row)
                    self.inline_bytes += sent + text
                    self.raw_bytes += size
                    return
            try:
                self._open()
            except (OSError, UnicodeError) as exc:
                self._drop_file(exc)
        if self.fh:
            try:
                self._write(self.total, row)
            except (OSError, UnicodeError) as exc:
                self._drop_file(exc)

    @property
    def _tmp(self):
        return self.tmp

    def finish(self):
        info = {"row_count": self.total, "returned": len(self.page), "truncated": self.total > len(self.page)}
        if self.fh:
            try:
                self.fh.flush()
                os.fsync(self.fh.fileno())
                self.fh.close()
                self.path, self.shown = publish(self.tmp, self.path, self.shown)
                self.tmp = None
                info["rows_file"] = self.shown
                info["earlier_answers"] = earlier_answers(self.path)
                info["rows_file_format"] = "JSON Lines: a header line {columns}, then one {n, values} per row; NULL is null, a BLOB is {blob_b64, length, sha256}"
                if self.file_stopped:
                    info["rows_file_stopped_at_row"] = self.file_stopped
                    info["rows_file_cap_bytes"] = FILE_BYTES
            except OSError as exc:
                self._drop_file(exc)
        if self.error:
            info["rows_file_error"] = self.error
        return info


def render(rows, columns, csv_mode):
    """The old tool's text for the inline page: CSV with a header, or the shell's list mode."""
    buf = io.StringIO()
    raw = [r for r in rows.raw_page]
    if csv_mode:
        w = csv.writer(buf, lineterminator="\n")
        w.writerow(columns)
        for r in raw:
            w.writerow([text_cell(v, True) for v in r])
    else:
        for r in raw:
            buf.write("|".join(text_cell(v, False) for v in r) + "\n")
    return buf.getvalue()


# --- values to a file (write_values) ---------------------------------------------------------------------------

VALUES_NAME = "sqlite-query-values.jsonl"
VALUES_FORMAT = ("JSON Lines, mode 0600: one line per cell that is not NULL (finding_id, table: the real name, rowid: null unless the "
                 "answer's locator is rowid, n: the row's position in this export from 1, column: the real name, type, length, and value: "
                 "a BLOB is {blob_b64}, text that is not UTF-8 is {text_invalid_utf8, bytes_b64, length}; a cell that could not be "
                 "exported has not_exported: value_too_large or unreadable instead of a value, and an unreadable one its error_class and "
                 "sqlite's message), then one last line {end: true, complete, rows_read, cells_written, cells_with_a_value, "
                 "cells_not_exported, stopped, error_class, sqlite_message}. A file without the end line was cut short (the run was killed "
                 "or the disk was full). No digest of any value")
VALUES_PARAMS = ("table", "columns", "rowid_from", "rowid_to")
ROWID_NAMES = ("rowid", "oid", "_rowid_")
LOCATORS_BYTES = FILE_BYTES       # the locators file stops here, and says so; the values file still has every cell's locator
PARTS_MAX = 1000                  # rows read again a cell at a time (a value over VALUE_MAX, a cell sqlite cannot compute); past it the export stops, said

# What each kind of table is located by, and in what order its rows come (the answer's n_ranks names the columns whose values that
# order follows). A rowid range is offered only where the rowid is not the value of a column the table declares.
LOCATOR_TEXT = {
    "rowid": "rowid: the table's own row key (it is no column's value), rows in rowid order",
    "alias": ("n: the row's position in this export. The table's rowid is the value of its INTEGER PRIMARY KEY column, so it is not "
              "printed; the rows come in the order of that key, so n ranks its values and says nothing more of them"),
    "without_rowid": ("n: the row's position in this export. A WITHOUT ROWID table has no rowid and its rows come in the order of its "
                      "primary key (its columns, collations and directions), so n ranks the key's values and says nothing more of them"),
    "virtual": ("n: the row's position in this export, in the order the virtual table's module returns rows, which can be the order of a "
                "value (fts5vocab returns its terms sorted); its rowid is not printed"),
    "shadowed": ("n: the row's position in this export, in rowid order; every name of the rowid (rowid, oid, _rowid_) is a column of this "
                 "table. Where one of them is the INTEGER PRIMARY KEY (n_ranks names it), the rowid is that column's value and n ranks it"),
}
NO_RANGE = {
    "alias": ("the table's rowid is the value of its INTEGER PRIMARY KEY column, so a rowid range would select rows by that value: "
              "export the whole table (rows are located by n)", "rowid_is_a_value"),
    "without_rowid": ("rowid_from and rowid_to select by rowid, and this table has none (WITHOUT ROWID): export the whole table", "no_rowid"),
    "virtual": ("a virtual table's rowid is whatever its module makes it, possibly a value: export the whole table", "virtual_table"),
    "shadowed": ("every name of the rowid (rowid, oid, _rowid_) is a column of this table, so no range can name it: export the whole table", "rowid_shadowed"),
}


def safe_name(text):
    return re.sub(r"[^A-Za-z0-9_.-]", "_", text)


def describe(exc):
    code = errno.errorcode.get(exc.errno, "") if getattr(exc, "errno", None) else ""
    return scrub("%s%s: %s" % (type(exc).__name__, " " + code if code else "", getattr(exc, "strerror", None) or str(exc)))


# What reading a row can raise: sqlite's errors, and Python's when it cannot decode the message of one (a UnicodeDecodeError, a
# ValueError: a generated column's error that quotes bytes that are not UTF-8 arrives as one, with no code).
READ_ERRORS = (sqlite3.Error, ValueError)
SQLITE_INTERRUPT, SQLITE_TOOBIG, SQLITE_AUTH = 9, 18, 23
SQLITE_ERROR_MISSING_COLLSEQ = 1 | (1 << 8)
# The fixed messages sqlite gives those codes (the wording of a denial changed between versions), for a Python that gives no code.
FIXED_MESSAGES = {"interrupted": SQLITE_INTERRUPT, "string or blob too big": SQLITE_TOOBIG, "not authorized": SQLITE_AUTH,
                  "authorization denied": SQLITE_AUTH}


def sqlite_code(exc):
    """The primary result code of a sqlite error, or None. Every decision is taken on the code, never on the message, which can
    quote a value (a generated column's json_extract does: "bad JSON path: 'it was interrupted'" must not end an export as a
    time-out). Python before 3.11 gives no code: there the text before the message's first quote decides, and only when it is,
    word for word, one of the fixed messages above, so a quoted value decides nothing. A UnicodeDecodeError (a message that
    quotes bytes that are not UTF-8) is none of these codes, whose messages are ASCII."""
    if not isinstance(exc, sqlite3.Error):
        return None
    code = getattr(exc, "sqlite_errorcode", None)
    if isinstance(code, int) and not isinstance(code, bool):
        return code & 0xFF
    head = re.split(r"['\"`\[]", str(exc), maxsplit=1)[0].strip().lower()
    return FIXED_MESSAGES.get(head)


def sqlite_class(exc):
    """The class of a sqlite error, never its message (a message can quote a value)."""
    if isinstance(exc, UnicodeDecodeError):
        return "UnicodeDecodeError (sqlite's message is not UTF-8)"
    name = getattr(exc, "sqlite_errorname", None)
    return "%s%s" % (type(exc).__name__, " " + name if isinstance(name, str) and re.fullmatch(r"SQLITE_[A-Z_]+", name) else "")


def sqlite_text(exc):
    """sqlite's message, for the values file only: bytes Python could not decode are kept, escaped."""
    if isinstance(exc, UnicodeDecodeError) and isinstance(exc.object, (bytes, bytearray)):
        return bytes(exc.object).decode("utf-8", "backslashreplace")
    return str(exc)


def refused_function(exc):
    """The authorizer refused a function (sqlite says so with SQLITE_ERROR, not SQLITE_AUTH): the message starts with sqlite's own
    fixed words, which no value comes before."""
    return isinstance(exc, sqlite3.Error) and str(exc).startswith("not authorized to use function: ")


def too_big(exc):
    return sqlite_code(exc) == SQLITE_TOOBIG


def missing_collation(exc):
    """sqlite has no collation of the name the schema gives (SQLITE_ERROR_MISSING_COLLSEQ, an extended code; on Python before 3.11,
    which gives none, sqlite's own fixed words, which no value comes before: the name after them is the schema's)."""
    if not isinstance(exc, sqlite3.Error):
        return False
    code = getattr(exc, "sqlite_errorcode", None)
    if isinstance(code, int) and not isinstance(code, bool):
        return code == SQLITE_ERROR_MISSING_COLLSEQ
    return str(exc).startswith("no such collation sequence: ")


def stops_the_export(exc):
    """An error no row-by-row reading gets past: the time budget, the authorizer (by their codes)."""
    return sqlite_code(exc) in (SQLITE_INTERRUPT, SQLITE_AUTH)


class SecretValuesRefused(Exception):
    pass


# A whole line of the values file, read back after a failed write: its kind and row are found in its head, before its value. Every
# `"` inside a JSON string is written `\"`, so these keys are matched only where they are keys.
_LINE_N = re.compile(rb'"n": (\d+), "column": ')
_LINE_VALUE = re.compile(rb'"length": (?:\d+|null), "value": ')
_LINE_MISSING = re.compile(rb'"length": (?:\d+|null), "not_exported": "([a-z_]+)"')


def _line_kind(head):
    if head.startswith(b'{"end": true'):
        return "end"
    if _LINE_VALUE.search(head):
        return "value"
    m = _LINE_MISSING.search(head)
    return m.group(1).decode("ascii") if m else None


class SecretValues:
    """Where a value goes when, and only when, the caller asked for it.

    The pattern of recovery_key_scan (encrypted-containers), copied: call `add` once per cell with its id, its locator and the
    value. With `enabled` false it writes nothing and `summary()` says so. `add_blob` is `add` for a BLOB written in slices.
    A write that fails (a full disk) raises OSError to the caller, which stops the export and says so; `close` never raises: what
    it could not do is in `error`, the file stays as far as it was written, without its end line, and the counts are then what
    the disk holds (`disk`), read back.
    """

    def __init__(self, enabled):
        self.enabled = enabled
        self.written = 0                     # cell lines: a value, or a not_exported line
        self.valued = 0                      # cell lines that hold a value
        self.missing = collections.Counter()  # not_exported lines, by why
        self.bytes = 0
        self._fh = None
        self.error = None
        self.ended = False
        self.disk = None
        self.job = os.environ.get("JOB_ID") or ""
        self.out = os.environ.get("OUT") or ""
        self.path = None
        self.shown = None
        if not enabled:
            return
        refusal = values_refusal()
        if refusal:
            raise SecretValuesRefused(refusal)
        self.path = Path(self.out) / VALUES_NAME
        self.shown = "store/jobs/%s/out/%s" % (safe_name(self.job), VALUES_NAME)
        # Created once the table is known and before its first row is read: a file or a link already at that name is refused by
        # name (O_EXCL does not follow a link, a dangling one included), instead of failing, or writing through it, after the
        # export. With nothing to write it stays an empty file but for its end line, mode 0600, and the answer says written: 0.
        # OUT itself first: a file or a link to nothing at OUT is said as such, not as a values file that exists.
        out_dir = self.path.parent
        try:
            out_dir.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            if os.path.islink(str(out_dir)) and not os.path.exists(str(out_dir)):
                raise SecretValuesRefused("OUT is a link to nothing (its target does not exist), not a directory: %s; nothing was "
                                          "written" % out_dir)
            if os.path.lexists(str(out_dir)) and not os.path.isdir(str(out_dir)):
                raise SecretValuesRefused("OUT is not a directory (a file is at its name): %s; nothing was written" % out_dir)
            raise SecretValuesRefused("OUT could not be made: %s (%s); nothing was written" % (out_dir, describe(exc)))
        try:
            fd = os.open(str(self.path), os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        except FileExistsError:
            raise SecretValuesRefused("the values file already exists: %s" % self.path)
        except OSError as exc:
            raise SecretValuesRefused("the values file could not be created: %s (%s)" % (self.path, describe(exc)))
        self._fh = os.fdopen(fd, "w", encoding="utf-8")

    def add(self, finding_id, locator, value):
        if not self.enabled:
            return
        line = json.dumps({"finding_id": finding_id, **locator, "value": value}) + "\n"
        self._fh.write(line)
        self.bytes += len(line)
        self.written += 1
        self.valued += 1

    def add_blob(self, finding_id, locator, blob):
        """A BLOB as {blob_b64}, written slice by slice: no second copy of a large value in memory, and no digest of it."""
        if not self.enabled:
            return
        head = json.dumps({"finding_id": finding_id, **locator})[:-1] + ', "value": {"blob_b64": "'
        self._fh.write(head)
        view = memoryview(blob)
        for at in range(0, len(view), SLICE_BYTES):
            self._fh.write(base64.b64encode(view[at:at + SLICE_BYTES]).decode("ascii"))
        self._fh.write('"}}\n')
        self.bytes += len(head) + 4 * ((len(blob) + 2) // 3) + 4
        self.written += 1
        self.valued += 1

    def add_missing(self, finding_id, locator, why, error=None, message=None):
        """A cell that is in the table and not in the file, said where its value would be (with sqlite's message, which can quote
        a value and is therefore written here only)."""
        if not self.enabled:
            return
        extra = {"error_class": error, "sqlite_message": message} if error else {}
        line = json.dumps({"finding_id": finding_id, **locator, "not_exported": why, **extra}) + "\n"
        self._fh.write(line)
        self.bytes += len(line)
        self.written += 1
        self.missing[why] += 1

    def end(self, record):
        """The last line: the file is whole up to here. A file without it was cut short."""
        if not self.enabled or self._fh is None or self.error:
            return
        try:
            self._fh.write(json.dumps({"end": True, **record}) + "\n")
            self.ended = True
        except OSError as exc:
            self.fail(exc)

    def fail(self, exc):
        if self.error is None:
            self.error = describe(exc)
        self.ended = False

    def disk_state(self):
        """What reached the disk, read back after a failed write, since a buffered writer takes more than a full disk keeps: the
        whole cell lines, how many hold a value and how many say not_exported (by why), the row of the last whole cell line,
        whether a part of a line follows the whole ones, and whether the last whole line is the end line. Read in blocks; of a
        line only its head is held, up to its value."""
        try:
            fd = os.open(str(self.path), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        except OSError:
            return None
        st = {"cell_lines": 0, "values": 0, "not_exported": collections.Counter(), "last_row": None, "part_of_a_line": False,
              "end_line": False}
        head, kind = b"", None
        with os.fdopen(fd, "rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                pos = 0
                while True:
                    nl = chunk.find(b"\n", pos)
                    stop = len(chunk) if nl < 0 else nl
                    if kind is None:
                        head += chunk[pos:stop]
                        kind = _line_kind(head)
                    if nl < 0:
                        break
                    if kind == "end":
                        st["end_line"] = True
                    else:
                        st["end_line"] = False
                        st["cell_lines"] += 1
                        if kind == "value":
                            st["values"] += 1
                        elif kind:
                            st["not_exported"][kind] += 1
                        m = _LINE_N.search(head)
                        st["last_row"] = int(m.group(1)) if m else st["last_row"]
                    head, kind = b"", None
                    pos = nl + 1
        if head:
            st["part_of_a_line"], st["end_line"] = True, False
        st["not_exported"] = dict(st["not_exported"])
        return st

    def state_text(self):
        d = self.disk
        if d is None:
            return "it could not be read back, so what it holds is not known; it is kept, mode 0600"
        if d["end_line"]:
            return ("it is kept, mode 0600, and reads whole: %d cell line(s) and its end line, so the error came at its close or its "
                    "sync and the disk's copy is not confirmed" % d["cell_lines"])
        return ("it is kept, mode 0600, with %d whole cell line(s)%s%s, and has no end line: it is not the table" % (
            d["cell_lines"], " (the last of row n=%d)" % d["last_row"] if d["last_row"] else "",
            ", then a part of a line" if d["part_of_a_line"] else ""))

    def close(self):
        if self._fh is None:
            return
        fh, self._fh = self._fh, None
        try:
            fh.flush()
            os.fsync(fh.fileno())
        except OSError as exc:
            self.fail(exc)
        try:
            fh.close()
        except OSError as exc:
            self.fail(exc)
            try:
                os.close(fh.fileno())
            except (OSError, ValueError):
                pass
        if self.error:
            self.disk = self.disk_state()
            if self.disk is not None:
                self.written, self.valued = self.disk["cell_lines"], self.disk["values"]
                self.missing = collections.Counter(self.disk["not_exported"])
                self.ended = self.disk["end_line"]
            else:
                self.ended = False
            self.error = "the values file could not be written to the end (%s); %s" % (self.error, self.state_text())

    def summary(self):
        lines_missing = sum(self.missing.values())
        return {
            "requested": self.enabled,
            "written": self.written,
            "values": self.valued,
            "not_exported": lines_missing,
            "values_file": self.shown if self.enabled else None,
            # A not_exported line carries sqlite's message, which can quote a value: it is secret too.
            "contains_secret_values": self.valued + lines_missing > 0,
            "format": VALUES_FORMAT if self.enabled else None,
            "end_line_written": self.ended,
        }


REFUSED_OUTSIDE_A_JOB = ("write_values is refused outside a job: a value written here would be an ordinary file, not a sealed secret "
                         "output. Run it as job_run(tool: \"sqlite_query\", secret_output: true, args: {...}) and ask again there. "
                         "Nothing was written.")
REFUSED_NOT_SECRET = ("write_values is refused in a job that was not run as secret output: its files would be sealed as ordinary output. "
                      "The harness sets SECRET_OUTPUT=1 for a secret job's process and it is not set here. Run it as "
                      "job_run(tool: \"sqlite_query\", args: {...}), whose manifest makes the job secret output, or give a command job "
                      "secret_output: true; if that is refused the same way, this run's harness does not set the variable and the values "
                      "mode is not available in it. Nothing was written.")


def values_refusal():
    """Why write_values cannot be honoured here, or None: outside a job (JOB_ID and OUT not both set), or in a job the harness did not
    run as secret output (SECRET_OUTPUT not 1). Decided before anything is opened or written."""
    if not (os.environ.get("JOB_ID") and os.environ.get("OUT")):
        return REFUSED_OUTSIDE_A_JOB
    if os.environ.get("SECRET_OUTPUT") != "1":
        return REFUSED_NOT_SECRET
    return None


def values_fail(message, **extra):
    say({"ok": False, "error": message, "tool": TOOL, **extra}, 1)


def q_ident(name):
    return '"' + name.replace('"', '""') + '"'


def value_kind(value):
    """(type, length) of a cell: the length is bytes for a BLOB and for text (as UTF-8), characters of its decimal form for an
    integer, and characters of Python's shortest repr for a real (1e+20 is 5, 12345.6 is 7: not its magnitude)."""
    if value is None:
        return "null", None
    if isinstance(value, NotExported):
        return value.kind, value.length
    if isinstance(value, bytes):
        return "blob", len(value)
    if isinstance(value, _Text):
        return "text_not_utf8", len(value.raw)
    if isinstance(value, str):
        return "text", len(value.encode("utf-8", "replace"))
    if isinstance(value, float):
        return "real", len(repr(value))
    return "integer", len(str(value))


def value_json(value):
    if isinstance(value, float) and (math.isnan(value) or math.isinf(value)):
        return {"real": repr(value)}
    if isinstance(value, _Text):
        return {"text_invalid_utf8": str(value), "bytes_b64": base64.b64encode(value.raw).decode("ascii"), "length": len(value.raw)}
    return value


END_RESERVE = 4096                # room kept for the end line but for sqlite's message in it


def line_reserve(finding_id, locator, value):
    """The most bytes the values file's line for this cell can take, from what the answer prints of the cell (its locator, type
    and length: never its content): six per byte of text (the longest JSON escape of a byte, \\u0001), the exact base64 of a BLOB,
    an integer's or a real's own characters. The cap is decided on these, so where an export stops does not depend on how a value
    escapes, and the file stays within the cap since a line is never longer. A not_exported line reserves six per byte of sqlite's
    message, whose length can follow a value it quotes."""
    base = len(json.dumps({"finding_id": finding_id, **locator})) + 1      # the line but its last key, and its newline
    if isinstance(value, NotExported):
        extra = len(', "not_exported": ""') + len(value.why)
        if value.error:
            # The class is one of a few fixed names (it can say whether the message was UTF-8: a fixed room hides that).
            extra += (len(', "error_class": , "sqlite_message": ') + max(256, len(json.dumps(value.error)))
                      + 6 * len((value.message or "").encode("utf-8", "replace")) + 2)
        return base + extra
    extra = len(', "value": ')
    if isinstance(value, bytes):
        return base + extra + len('{"blob_b64": ""}') + 4 * ((len(value) + 2) // 3)
    if isinstance(value, _Text):
        n = len(value.raw)
        return base + extra + len('{"text_invalid_utf8": , "bytes_b64": "", "length": }') + 6 * n + 2 + 4 * ((n + 2) // 3) + len(str(n))
    if isinstance(value, str):
        return base + extra + 6 * len(value.encode("utf-8", "replace")) + 2
    if isinstance(value, float):
        return base + extra + max(len(repr(value)), len('{"real": "-inf"}'))
    return base + extra + len(str(value))


class NotExported:
    """A cell whose value is not in the values file: `value_too_large` (longer than VALUE_MAX: its type, and its length when SQLite
    gives it without reading the value) or `unreadable` (sqlite could not compute it: a generated column's error)."""

    def __init__(self, why, kind, length=None, error=None, message=None):
        self.why, self.kind, self.length, self.error, self.message = why, kind, length, error, message


def blank_quoted(sql):
    """A CREATE statement with its strings, quoted names and comments blanked: a default value, a name or a comment can hold any
    words."""
    out, i, n = [], 0, len(sql)
    while i < n:
        ch = sql[i]
        if ch in "'\"`":
            j = i + 1
            while j < n:
                if sql[j] == ch:
                    if j + 1 < n and sql[j + 1] == ch:   # a doubled quote is one quote inside
                        j += 2
                        continue
                    break
                j += 1
            i = j + 1
            out.append(" ")
        elif ch == "[":
            j = sql.find("]", i + 1)
            i = n if j < 0 else j + 1
            out.append(" ")
        elif sql.startswith("--", i):
            j = sql.find("\n", i)
            i = n if j < 0 else j + 1
            out.append(" ")
        elif sql.startswith("/*", i):
            j = sql.find("*/", i + 2)
            i = n if j < 0 else j + 2
            out.append(" ")
        else:
            out.append(ch)
            i += 1
    return "".join(out)


def declared_without_rowid(sql):
    """Whether a CREATE TABLE statement carries the WITHOUT ROWID option: the words after the column list's closing parenthesis."""
    text = blank_quoted(sql)
    return ")" in text and bool(re.search(r"\bWITHOUT\s+ROWID\b", text[text.rfind(")") + 1:], re.I))


def table_list_row(conn, table):
    """The table's row of PRAGMA table_list (SQLite 3.37 and later: schema, name, type, ncol, wr, strict), or None."""
    try:
        for r in conn.execute("PRAGMA table_list"):
            if len(r) > 4 and str(r[0]) == "main" and str(r[1]) == table:
                return r
    except READ_ERRORS:
        pass
    return None


def is_virtual(conn, table, sql, rootpage):
    """SQLite's own answer where it gives one (table_list's type), else the schema: a virtual table has no b-tree (rootpage 0), and
    its statement says VIRTUAL once its strings, quoted names and comments are blanked (CREATE /* x */ VIRTUAL TABLE is one, in a
    schema an application or a crafted file wrote)."""
    r = table_list_row(conn, table)
    if r is not None:
        return str(r[2]) == "virtual"
    return rootpage == 0 or bool(re.match(r"\s*create\s+virtual\s+table\b", blank_quoted(sql), re.I))


def is_without_rowid(conn, table, sql):
    """SQLite's own answer where it gives one (PRAGMA table_list, SQLite 3.37 and later: its `wr` column), else the statement's
    text. Decided before the names: columns named rowid, oid and _rowid_ hide the rowid of a rowid table and change nothing of a
    WITHOUT ROWID one."""
    r = table_list_row(conn, table)
    if r is not None:
        return bool(r[4])
    return declared_without_rowid(sql)


def primary_key_order(conn, table, info):
    """A WITHOUT ROWID table's primary key as the table stores it: (its columns, an ORDER BY of each with its collation and
    direction), so SQLite reads the table's own b-tree, or an index in the same order, and needs no sort. From PRAGMA
    index_xinfo of the key, else the key's columns from table_xinfo."""
    try:
        for r in conn.execute("PRAGMA index_list(%s)" % q_ident(table)):
            if str(r[3]) == "pk":
                keys = [x for x in conn.execute("PRAGMA index_xinfo(%s)" % q_ident(str(r[1]))) if x[5]]
                if keys and all(x[2] is not None for x in keys):
                    return [str(x[2]) for x in keys], ", ".join(
                        "%s COLLATE %s%s" % (q_ident(str(x[2])), q_ident(str(x[4] or "BINARY")), " DESC" if x[3] else "") for x in keys)
    except READ_ERRORS:
        pass
    key = [str(r[1]) for r in sorted((r for r in info if r[5]), key=lambda r: r[5])]
    return key, ", ".join(q_ident(k) for k in key)


def byte_compare(a, b):
    """The stand-in for a collation this SQLite does not have: code point order, which is UTF-8's byte order."""
    return (a > b) - (a < b)


def stand_in_collations(conn, table):
    """The collations a WITHOUT ROWID table's primary key names that this SQLite does not have (an application's own: Android's
    LOCALIZED and UNICODE), each given a byte compare, so that the key's ORDER BY can be prepared. SQLite then walks the table's
    b-tree in the order it is stored and sorts nothing (the ORDER BY names the key's own collations), so the rows come in the
    order the application's collation gave them; a comparison under that name in the table's own expressions (a generated
    column) is the byte compare's. Only a name sqlite says is missing gets one (asked of a constant, not of a value)."""
    names = []
    try:
        for r in conn.execute("PRAGMA index_list(%s)" % q_ident(table)):
            if str(r[3]) == "pk":
                for x in conn.execute("PRAGMA index_xinfo(%s)" % q_ident(str(r[1]))):
                    if x[5] and isinstance(x[4], str) and x[4] and x[4] not in names:
                        names.append(x[4])
    except READ_ERRORS:
        return []
    stood = []
    for name in names:
        try:
            conn.execute("SELECT 'a' < 'b' COLLATE %s" % q_ident(name)).fetchone()
        except READ_ERRORS as exc:
            if not missing_collation(exc):
                continue
            try:
                conn.create_collation(name, byte_compare)
                stood.append(name)
            except (sqlite3.Error, ValueError, TypeError):
                pass
    return stood


def integer_primary_key(conn, table, info):
    """The column SQLite makes the rowid of a rowid table, or None: its one primary key column when declared exactly INTEGER (any
    case of the ASCII word) and kept in no index of its own. `INTEGER PRIMARY KEY DESC` is not an alias, and SQLite then makes the
    key an index (origin pk in PRAGMA index_list); where that list cannot be read the declared type alone decides, which can only
    hide a rowid that could have been shown."""
    pk = [r for r in info if r[5]]
    declared = str(pk[0][2] or "").strip() if len(pk) == 1 else ""
    if not (declared.isascii() and declared.upper() == "INTEGER"):
        return None
    try:
        if any(str(r[3]) == "pk" for r in conn.execute("PRAGMA index_list(%s)" % q_ident(table))):
            return None
    except READ_ERRORS:
        pass
    return str(pk[0][1])


def table_layout(conn, wanted, columns):
    """(table, [(column, declared type)], kind, order) for the table `wanted`, or a refusal as JSON. `kind` is how a row is located:
    rowid (an ordinary rowid table), alias (its rowid is an INTEGER PRIMARY KEY column's value), without_rowid, virtual, or
    shadowed (a rowid table whose columns named rowid, oid and _rowid_ hide the rowid). `order` says how its rows are read:
    rowid_name (the name that reaches the rowid, kind rowid only), order_by (an ORDER BY that is the table's own order and total,
    or None: a shadowed table with no INTEGER PRIMARY KEY is read NOT INDEXED in its storage order, a virtual table in its
    module's), and ranks (the columns whose values that order follows: [] for a rowid order that is no column's, None for a
    module's, which is not known)."""
    rows = list(conn.execute("SELECT name, sql, rootpage FROM sqlite_master WHERE type = 'table' ORDER BY name"))
    found = [(str(r[0]), r[1] if isinstance(r[1], str) else "") for r in rows]
    roots = {str(r[0]): r[2] for r in rows}
    names = [n for n, _s in found]
    hits = [n for n in names if n == wanted] or [n for n in names if n.lower() == wanted.lower()]
    if len(hits) != 1:
        values_fail("the database has no table of that name (the mode reads one table; a view is not one)" if not hits
                    else "more than one table matches that name without regard to case: give it exactly", table=wanted, tables=len(names))
    table = hits[0]
    virtual = is_virtual(conn, table, dict(found)[table], roots[table])
    try:
        info = [r for r in conn.execute("PRAGMA table_xinfo(%s)" % q_ident(table)) if r[6] in (0, 2, 3)]
    except READ_ERRORS as exc:
        if virtual:
            raise VirtualTableUnsupported(exc)
        raise
    have = {str(r[1]): str(r[2] or "") for r in info}
    chosen = columns if columns is not None else [str(r[1]) for r in info]
    if not chosen:
        values_fail("the table has no column that can be read", table=table)
    for c in chosen:
        if c not in have:
            values_fail("the table has no column of that name (names are case-sensitive here)", table=table, column=c)
    layout = [(c, have[c]) for c in chosen]
    if virtual:
        return table, layout, "virtual", {"rowid_name": None, "order_by": None, "ranks": None}
    lowered = {str(r[1]).lower() for r in info}
    rowid_name = next((cand for cand in ROWID_NAMES if cand not in lowered), None)
    no_rowid = is_without_rowid(conn, table, dict(found)[table])
    if not no_rowid and rowid_name is not None:
        try:
            conn.execute("SELECT %s FROM %s LIMIT 0" % (rowid_name, q_ident(table)))
        except READ_ERRORS:
            no_rowid = True                       # SQLite has no rowid for it, whatever the statement's text says
    if no_rowid:
        # Ordered by the primary key as the table stores it: without an ORDER BY SQLite reads a WITHOUT ROWID table through a
        # covering index, in the order of another column's values, NOT INDEXED or not (columns named rowid, oid and _rowid_ change
        # nothing of that).
        key, order_by = primary_key_order(conn, table, info)
        return table, layout, "without_rowid", {"rowid_name": None, "order_by": order_by or None, "ranks": key}
    alias = integer_primary_key(conn, table, info)
    if rowid_name is None:
        # Every name of the rowid is a column. Where one column is the INTEGER PRIMARY KEY it is the rowid, and the rows are ordered
        # by it; otherwise no name reaches the rowid, and the rows are read NOT INDEXED in storage order (rowid order).
        return table, layout, "shadowed", {"rowid_name": None, "order_by": q_ident(alias) if alias else None, "ranks": [alias] if alias else []}
    if alias:
        # Its value is the rowid: the rows are ordered by the rowid, which is that column's order (n ranks it); no WHERE names it.
        return table, layout, "alias", {"rowid_name": None, "order_by": rowid_name, "ranks": [alias]}
    return table, layout, "rowid", {"rowid_name": rowid_name, "order_by": rowid_name, "ranks": []}


def export_statement(table, kind, order, what, bounds=None):
    """(statement, parameters) that read `what` from the table: from the table itself (NOT INDEXED: an index's order is the order
    of the indexed values), in the table's own order (a WITHOUT ROWID table's key, which an index can only follow), and on a
    rowid table within the rowid range. The tests read its plan."""
    stmt = "SELECT %s FROM %s%s" % (what, q_ident(table), "" if kind == "virtual" else " NOT INDEXED")
    params, conds = [], []
    if kind == "rowid":
        for key, op in (("rowid_from", ">="), ("rowid_to", "<=")):
            if bounds and key in bounds:
                conds.append("%s %s ?" % (order["rowid_name"], op))
                params.append(bounds[key])
    if conds:
        stmt += " WHERE " + " AND ".join(conds)
    if order["order_by"]:
        stmt += " ORDER BY " + order["order_by"]
    return stmt, params


class VirtualTableUnsupported(Exception):
    pass


def values_mode(obj, given, db, size, side, status, snap, limit, budget, csv_mode):
    wanted = obj.get("table")
    if not isinstance(wanted, str) or not wanted:
        values_fail("write_values needs table: the one table whose values go to the file")
    columns = obj.get("columns")
    if columns is not None and (not isinstance(columns, list) or not columns or not all(isinstance(c, str) and c for c in columns)
                                or len(set(columns)) != len(columns)):
        values_fail("columns is a list of distinct column names, or left out for every column")
    bounds = {}
    for key in ("rowid_from", "rowid_to"):
        if key in obj:
            v = obj[key]
            if not isinstance(v, int) or isinstance(v, bool) or not -2 ** 63 <= v < 2 ** 63:
                values_fail("%s is a whole number from -2**63 to 2**63-1" % key)
            bounds[key] = v
    for name, text in [("table", wanted)] + [("columns", c) for c in columns or []]:
        if "\0" in text:
            values_fail("%s holds a NUL character" % name)
        try:
            text.encode("utf-8")
        except UnicodeEncodeError:
            values_fail("%s is not text that can be written as UTF-8 (it holds a lone surrogate)" % name)
    uri = "file:%s?mode=ro&immutable=1" % urllib.parse.quote(db)
    started = time.monotonic()
    try:
        conn = connect_checked(db, uri)
    except READ_ERRORS as exc:
        values_fail("cannot open the database (%s)" % sqlite_class(exc), db_path=db)
    watch = SqliteWatch(started + budget)     # the budget and a stop end a statement SQLite runs in C, where the progress handler is not called (SQLITE WATCH)
    watch.watch(conn)
    conn.text_factory = text_factory
    value_limit = "%d bytes" % VALUE_MAX
    if hasattr(conn, "setlimit") and hasattr(sqlite3, "SQLITE_LIMIT_LENGTH"):
        conn.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, VALUE_MAX)
    else:
        value_limit = "not enforced (Python before 3.11 has no setlimit)"
    conn.set_authorizer(authorizer)
    conn.set_progress_handler(lambda: 1 if time.monotonic() - started > budget else 0, 20000)
    try:
        table, cols, kind, order = table_layout(conn, wanted, columns)
        rowid_name = order["rowid_name"]
    except VirtualTableUnsupported as exc:
        values_fail("the table is a virtual table whose module could not be started under the read-only authorizer (%s): this "
                    "SQLite cannot export it here; its shadow tables (<name>_content, <name>_data, ...) are ordinary tables that can be"
                    % sqlite_class(exc.args[0]), table=wanted, reason="virtual_table_unsupported")
    except READ_ERRORS as exc:
        values_fail("the table's layout cannot be read (%s)" % sqlite_class(exc), table=wanted)
    if bounds and kind != "rowid":
        why, reason = NO_RANGE[kind]
        values_fail(why, table=table, reason=reason)
    stood_in = stand_in_collations(conn, table) if kind == "without_rowid" else []
    # The values file is made now: the table exists and its layout is read, and no row has been. A wrong name or a file that is
    # not SQLite leaves nothing behind, and the same job can ask again.
    try:
        values = SecretValues(True)
    except SecretValuesRefused as exc:
        say({"ok": False, "error": str(exc), "tool": TOOL, "write_values": "refused", "written": False}, 1)
    sel = ([rowid_name] if kind == "rowid" else []) + [q_ident(c) for c, _t in cols]

    def query(what, offset=None, one=False):
        stmt, params = export_statement(table, kind, order, what, bounds)
        if one:
            stmt += " LIMIT 1 OFFSET %d" % offset
        elif offset:
            stmt += " LIMIT -1 OFFSET %d" % offset
        return conn.execute(stmt, params)

    def one(what, offset):
        """One value of the row at `offset` (None when there is no such row)."""
        got = query(what, offset, one=True).fetchone()
        return None if got is None else got[0]

    def read_in_parts(offset):
        """The row at `offset`, because reading it whole failed: each cell is tried alone, then every cell that can be read is read
        in ONE query, so the cells of an exported row are always one row's (every query has the same total order, and the same
        LIMIT 1 OFFSET). A value over the length limit, and a cell sqlite cannot compute, are recorded instead of a value. A row
        skipped by OFFSET is not decoded, and typeof() and a BLOB's length() do not read the value. A row none of whose cells can
        be read is not a cell's fault: its first error is raised. None: there is no row at `offset`."""
        missing, first = {}, None
        for i, (c, _t) in enumerate(cols):
            ident = q_ident(c)
            try:
                if query(ident, offset, one=True).fetchone() is None:
                    return None
                continue
            except READ_ERRORS as exc:
                if stops_the_export(exc):
                    raise
                first = first or exc
                failed = exc
            try:
                kind_of = one("typeof(%s)" % ident, offset) or "unknown"
            except READ_ERRORS as exc:
                if stops_the_export(exc):
                    raise
                kind_of = "unknown"
            if too_big(failed):
                try:
                    length = one("%s(%s)" % ("length" if kind_of == "blob" else "octet_length", ident), offset)
                except READ_ERRORS as exc:
                    if stops_the_export(exc):
                        raise
                    length = None
                missing[i] = NotExported("value_too_large", kind_of, length if isinstance(length, int) else None)
            else:
                missing[i] = NotExported("unreadable", "unreadable", None, sqlite_class(failed), sqlite_text(failed))
        if first is not None and all(missing.get(i) is not None and missing[i].why == "unreadable" for i in range(len(cols))):
            raise first
        readable = [i for i in range(len(cols)) if i not in missing]
        what = ([rowid_name] if kind == "rowid" else []) + [q_ident(cols[i][0]) for i in readable]
        got = query(", ".join(what), offset, one=True).fetchone() if what else ()
        if got is None:
            return None
        got = list(got)
        row = [got.pop(0)] if kind == "rowid" else []
        for i in range(len(cols)):
            row.append(missing[i] if i in missing else got.pop(0))
        return tuple(row)

    names = [scrub(cell(c)) for c, _t in cols]
    stats = [{"values": collections.OrderedDict(), "length_min": None, "length_max": None} for _ in cols]
    page, page_bytes, total, nulls, file_stopped, file_stopped_rowid = [], 0, 0, 0, None, None
    reserved = 0                         # the values file's bytes as line_reserve counts them: what the cap is decided on
    missing, missing_count, parts = [], collections.Counter(), 0
    parts_limit = False
    job = os.environ.get("JOB_ID") or ""
    digest = hashlib.sha256(json.dumps([db, size, table, [c for c, _t in cols], sorted(bounds.items())], sort_keys=True, default=str).encode()).hexdigest()[:16]
    name = "sqlite_query-values-%s.jsonl" % digest
    locator_path = Path(os.environ["OUT"]) / "tool-output" / name
    locator_shown = "store/jobs/%s/out/tool-output/%s" % (safe_name(job), name)
    loc = {"fh": None, "tmp": None, "bytes": 0, "error": None, "stopped": None, "left": []}

    class _LocatorsHolder:
        @property
        def _tmp(self):
            return loc["tmp"]
    PAGES.append(_LocatorsHolder())
    failure = reason = None
    sqlite_message = error_class = None
    timed_out = False

    def shown_tmp(path):
        # The tool's own temporary name (mkstemp's), not the evidence's: printed as it is, or it could not be found.
        return "store/jobs/%s/out/tool-output/%s" % (safe_name(job), cell(os.path.basename(str(path))))

    def loc_drop(exc):
        try:
            if loc["fh"] is not None:
                loc["fh"].close()
        except OSError:
            pass
        loc["fh"] = None
        if loc["tmp"] is not None:
            try:
                loc["tmp"].unlink()
            except OSError:
                loc["left"].append(shown_tmp(loc["tmp"]))
            loc["tmp"] = None
        loc["error"] = "the locators file could not be written (%s); %s" % (
            describe(exc), "what was written of it is left, unnamed by the answer, at %s" % ", ".join(loc["left"]) if loc["left"] else "none is left")

    def loc_write(text, n):
        if loc["fh"] is None or loc["stopped"]:
            return
        if loc["bytes"] + len(text) > LOCATORS_BYTES:
            loc["stopped"] = n
            return
        try:
            loc["fh"].write(text)
            loc["bytes"] += len(text)
        except OSError as exc:
            loc_drop(exc)

    # The locators file is written for every export (it has every row; the inline page has the first ones).
    try:
        locator_path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp_name = temp_create(locator_path.parent, ".sqlite_query-")
        loc["tmp"] = Path(tmp_name)
        try:
            loc["fh"] = os.fdopen(fd, "w", encoding="utf-8")
        except BaseException:
            os.close(fd)
            raise
    except OSError as exc:
        loc_drop(exc)
    loc_write(json.dumps({"table": scrub(cell(table)), "columns": names, "locator": "rowid" if kind == "rowid" else "n"}) + "\n", 0)

    def take(row):
        """One row: its values to the values file (OSError: the values file failed), then, once the row is through, its locators to
        the answer and the locators file and its counts, so row_count N means rows 1..N in the locators file."""
        nonlocal total, nulls, file_stopped, file_stopped_rowid, page_bytes, reserved
        n = total + 1
        rid = row[0] if kind == "rowid" else None
        vals = row[1:] if kind == "rowid" else row
        cells, kinds, row_missing = [], [], []
        for i, ((col, _t), v) in enumerate(zip(cols, vals)):
            kind_of, length = value_kind(v)
            kinds.append((kind_of, length))
            if v is None:
                cells.append("null")
                continue
            if isinstance(v, NotExported):
                row_missing.append((i, v))
                cells.append("too_large:%s:%s" % (kind_of, "?" if length is None else length) if v.why == "value_too_large" else "unreadable")
            else:
                cells.append("%s:%d" % (kind_of, length))
            if file_stopped:
                continue
            finding = "V%07d" % (values.written + 1)
            locator = {"table": table, "rowid": rid, "n": n, "column": col, "type": kind_of, "length": length}
            need = line_reserve(finding, locator, v)
            if reserved + need > FILE_BYTES - END_RESERVE:
                file_stopped, file_stopped_rowid = n, rid
                continue
            reserved += need
            if isinstance(v, NotExported):
                values.add_missing(finding, locator, v.why, v.error, v.message)
            elif isinstance(v, bytes) and len(v) > STREAM_AT:
                values.add_blob(finding, locator, v)
            elif isinstance(v, bytes):
                values.add(finding, locator, {"blob_b64": base64.b64encode(v).decode("ascii")})
            else:
                values.add(finding, locator, value_json(v))
        total = n
        for st, (kind_of, length) in zip(stats, kinds):
            st["values"][kind_of] = st["values"].get(kind_of, 0) + 1
            if length is not None:
                st["length_min"] = length if st["length_min"] is None else min(st["length_min"], length)
                st["length_max"] = length if st["length_max"] is None else max(st["length_max"], length)
        nulls += sum(1 for kind_of, _l in kinds if kind_of == "null")
        for i, v in row_missing:
            missing_count[v.why] += 1
            stats[i].setdefault("not_exported", collections.Counter())[v.why] += 1
            if len(missing) < 100:
                missing.append({"n": n, "rowid": rid, "column": names[i], "why": v.why})
        line = json.dumps({"n": n, "rowid": rid, "cells": cells})
        if len(page) < limit and page_bytes + len(line) <= INLINE_BYTES:
            page.append({"n": n, "rowid": rid, "cells": cells})
            page_bytes += len(line)
        loc_write(line + "\n", n)

    def read_alone(offset):
        """The row at `offset` after reading the table failed there. Python's cursor steps to the next row before it hands over
        the current one, so the error can be the next row's: the row is read alone first, and a cell at a time only when that
        fails too (one charge against PARTS_MAX per such row). None: no row at `offset`."""
        nonlocal parts, parts_limit
        try:
            return query(", ".join(sel), offset, one=True).fetchone()
        except READ_ERRORS as exc:
            if stops_the_export(exc):
                raise
            if parts >= PARTS_MAX:
                parts_limit = True
                raise
            parts += 1
            return read_in_parts(offset)

    try:
        cur = None
        while True:
            try:
                if cur is None:
                    cur = query(", ".join(sel), total)
                row = next(cur, None)
            except READ_ERRORS as exc:
                if stops_the_export(exc) or kind == "virtual":
                    raise
                cur = None
                row = read_alone(total)
                if row is None:
                    raise
                take(row)
                continue
            if row is None:
                break
            take(row)
    except OSError as exc:
        values.fail(exc)
    except (sqlite3.Error, ValueError, OverflowError, MemoryError) as exc:
        # Nothing of the error is printed but what its code decides: sqlite's message can quote a value (a generated column's
        # json_extract does), and so can the class Python gives it (it cannot decode a message that quotes bytes that are not
        # UTF-8). The class and the message go to the values file's end line, the one place a value may be.
        code = sqlite_code(exc)
        sqlite_message = "MemoryError" if isinstance(exc, MemoryError) else sqlite_text(exc)
        error_class = sqlite_class(exc)
        where = "row n=%d (the first row not exported)" % (total + 1)
        if code == SQLITE_INTERRUPT:
            failure, reason, timed_out = "stopped at the %d-second time budget; the rows before it are in the values file" % budget, "timed_out", True
        elif code == SQLITE_AUTH:
            failure, reason = "the read-only authorizer refused what reading the table asked for; nothing past %s" % where, "not_a_plain_read"
        elif kind == "virtual":
            failure, reason = ("the virtual table's module failed at %s: this SQLite cannot export it here; its shadow tables are "
                               "ordinary tables that can be" % where), "virtual_table_unsupported"
        elif isinstance(exc, MemoryError):
            failure, reason = "out of memory reading %s" % where, "out_of_memory"
        elif parts_limit:
            failure, reason = ("%d rows had a cell that could not be read with the rest, the most read a cell at a time; the export "
                               "stopped at %s" % (PARTS_MAX, where)), "too_many_rows_read_in_parts"
        elif missing_collation(exc):
            failure, reason = ("%s could not be read: the table's schema names a collation this SQLite does not have (an "
                               "application's own), where no byte compare stands in (one does only for a WITHOUT ROWID table's "
                               "primary key). That is the schema's doing, not a value's; the collation's name is in sqlite's "
                               "message, in the values file's end line" % where), "missing_collation"
        else:
            failure, reason = ("%s could not be read: none of its cells. The error's class and sqlite's message are not printed, "
                               "since they can depend on a value; they are in the values file's end line" % where), "row_unreadable"
    finally:
        values.end({"complete": failure is None and file_stopped is None and not missing_count, "rows_read": total,
                    "cells_written": values.written, "cells_with_a_value": values.valued, "cells_not_exported": dict(values.missing),
                    "stopped": reason or ("values_file_cap" if file_stopped else None), "error_class": error_class,
                    "sqlite_message": sqlite_message})
        values.close()
        watch.close()
        try:
            conn.close()
        except sqlite3.Error:
            pass
    published = None
    if loc["fh"] is not None:
        try:
            loc["fh"].flush()
            os.fsync(loc["fh"].fileno())
            loc["fh"].close()
            loc["fh"] = None
            left = []
            published = publish(loc["tmp"], locator_path, locator_shown, left)
            loc["tmp"] = None
            loc["left"].extend(shown_tmp(p) for p in left)
        except OSError as exc:
            loc_drop(exc)

    out = {"tool": TOOL, "db_path": given, "database_bytes": size, "sidecars": side, "snapshot_status": status,
           "sqlite_library": sqlite3.sqlite_version, "opened": "read-only, immutable, through an authorizer that allows reading only",
           "value_limit": value_limit}
    if size <= HASH_MAX:
        out["database_sha256"] = sha256_file(db)
    else:
        out["database_sha256"] = None
        out["hashing"] = "skipped: the file is larger than %d bytes; the run's own record has its sha256" % HASH_MAX
    if db != given:
        out["database_opened"] = db
    if snap:
        snap["file_matches_recorded_sha256"] = (out["database_sha256"] == snap["recorded_sha256"]) if out["database_sha256"] and snap["recorded_sha256"] else None
        if snap["file_matches_recorded_sha256"] is False:
            out["snapshot_status"] = "THE FILE QUERIED IS NOT THE ONE THE SNAPSHOT RECORDED (its sha256 differs from the receipt's): it was changed after the snapshot, or the receipt belongs to another file. " + out["snapshot_status"]
        out["snapshot"] = snap
    # ok is false when the export stopped early or the values file could not be written to its end (as network_log_summary
    # says a read that stopped early); a locators file that could not be written leaves ok true and complete false, since the
    # values file is whole.
    if failure is None and values.error:
        failure, reason = "the values file could not be written to the end: the export stopped at row n=%d" % (total + 1), "values_file_error"
    complete = (failure is None and file_stopped is None and values.error is None and not missing_count
                and loc["error"] is None and loc["stopped"] is None and published is not None)
    shown_key = lambda p: p["rowid"] if p["rowid"] is not None else p["n"]
    text = "".join("%s|%s\n" % (shown_key(p), "|".join("%s=%s" % (nm, c) for nm, c in zip(names, p["cells"]))) for p in page)
    if csv_mode:
        buf = io.StringIO()
        w = csv.writer(buf, lineterminator="\n")
        w.writerow(["rowid" if kind == "rowid" else "n"] + names)
        for p in page:
            w.writerow([shown_key(p)] + p["cells"])
        text = buf.getvalue()
    out.update({
        "ok": failure is None, "returncode": 0 if failure is None else 1, "stderr": failure or "", "complete": complete,
        "mode": "values_to_file", "table": table, "table_kind": kind, "locator": "rowid" if kind == "rowid" else "n", "locator_note": LOCATOR_TEXT[kind],
        "n_ranks": None if order["ranks"] is None else [scrub(cell(c)) for c in order["ranks"]],
        "columns": [dict({"name": nm, "declared_type": scrub(cell(t)), "values": st["values"], "length_min": st["length_min"], "length_max": st["length_max"]},
                         **({"not_exported": dict(st["not_exported"])} if st.get("not_exported") else {}))
                    for nm, (_c, t), st in zip(names, cols, stats)],
        "row_count": total, "returned": len(page), "truncated": total > len(page), "rows": page,
        "cells_with_a_value": values.valued, "cells_null": nulls,
        "secret_values": values.summary(), "stdout": text,
    })
    if failure:
        out["error"] = failure
        out["reason"] = reason
        out["rows_read_before_the_stop"] = total
        if timed_out:
            out["timed_out"] = True
    if values.error:
        out["values_file_error"] = values.error
        d = values.disk
        out["values_file_state"] = ("unknown: " if d is None else "whole: " if d["end_line"] else "partial: ") + values.state_text()
        if d is not None:
            out["values_file_holds"] = {"cell_lines": d["cell_lines"], "values": d["values"], "not_exported": d["not_exported"],
                                        "last_row_with_a_whole_line": d["last_row"], "part_of_a_line_after": d["part_of_a_line"],
                                        "end_line": d["end_line"]}
    if missing_count:
        out["cells_not_exported"] = {"cells": dict(missing_count), "first": missing, "value_limit_bytes": VALUE_MAX,
                                     "note": ("value_too_large: longer than the limit; unreadable: sqlite could not compute the cell (the "
                                              "error's class and sqlite's message, which can quote a value, are in the values file only). "
                                              "Which cells are unreadable follows from the table's own expressions over its values (a "
                                              "generated column's json_extract fails on text that is not JSON), so it can say something "
                                              "of those values. Each such cell has a not_exported line in the values file%s; the rest of "
                                              "its row is exported" % (" (up to the row values_file_holds names)" if values.error else ""))}
    if stood_in:
        out["collations_stood_in"] = {
            "names": [scrub(cell(c)) for c in stood_in],
            "note": ("this SQLite does not have the collation(s) the table's primary key names (an application's own); a byte compare "
                     "stood in for each so that the key's order could be asked for. SQLite walks the table in the order it stores it "
                     "and sorts nothing, so the rows come in the order the application's collation gave them (n ranks the key, as for "
                     "any WITHOUT ROWID table); a comparison under that name in the table's own expressions (a generated column) is the "
                     "byte compare's, not the application's")}
    if published:
        out["locators_file"] = published[1]
        out["locators_file_format"] = "JSON Lines: a header line {table, columns, locator}, then one {n, rowid, cells} per row; a cell is type:length, too_large:type:length, unreadable or null; no value"
        out["earlier_answers"] = earlier_answers(published[0])
        if loc["stopped"]:
            out["locators_file_stopped_at_row"] = loc["stopped"]
            out["locators_file_cap_bytes"] = LOCATORS_BYTES
    if loc["left"]:
        out["locators_file_left"] = ("temporary file(s) that could not be removed: %s (each is the locators file or a part of it; no value "
                                     "is in it)" % ", ".join(loc["left"]))
    if loc["error"]:
        out["locators_file_error"] = loc["error"]
    if file_stopped:
        out["values_file_stopped_at_row"] = file_stopped
        out["values_file_cap_bytes"] = FILE_BYTES
        if kind == "rowid":
            out["resume"] = "in a new job (the values file of this one is kept), give rowid_from %d" % file_stopped_rowid
        else:
            out["resume"] = "this table has no rowid range (%s): export fewer columns per job" % NO_RANGE[kind][1]
    out["note"] = ("Locator output: no value, fragment, masked shape or digest of one is in this answer or in any file it names except the "
                   "values file. A cell is type:length (bytes for a BLOB and for text, characters of the decimal form for an integer, so "
                   "its length tells its order of magnitude; a real's is its shortest repr, which does not). The mode exports whole rows "
                   "of one table and takes no filter: row_count and the lengths are the table's (or the rowid range's). %s. Cite table, "
                   "the locator and column; hand a value on through the channel the operator named. The inline page is the first rows; "
                   "locators_file has every row." % LOCATOR_TEXT[kind])
    say(out, 0 if failure is None else 1)


def _stopped(signum):
    print(json.dumps({"tool": TOOL, "ok": False, "complete": False, "status": "partial", "interrupted": True, "signal": signum,
                      "status_basis": "the tool was stopped by signal %d: no result of the request is claimed, the files it was writing were removed, and a values file "
                                      "already begun holds the rows written before the stop" % signum}), flush=True)


# BEGIN SHARED SQLITE WATCH
# A statement SQLite runs in C stops neither at the tool's clock nor at a stop signal by itself. A step of SQLite runs with the interpreter's
# lock released: a progress handler is called only between the steps of SQLite's own program (one count(*) over a damaged b-tree is one
# step, OP_Count; so is a page of PRAGMA integrity_check or quick_check), and a Python signal handler runs only when the main thread is back
# in Python, so one step that walks a b-tree whose pages are reached from many parents neither ends at the clock nor answers a SIGTERM.
# SqliteWatch is a thread that waits on the deadline and on the signal wake-up pipe (the C-level handler writes the signal's number to it,
# whatever the main thread is doing) and calls interrupt() on every connection it watches: at the deadline, every TICK seconds after it (a
# statement begun later is ended too), and when a stop signal (SIGTERM, SIGINT, SIGHUP) arrives; another signal (a SIGALRM of a regular
# expression's clock) ends nothing. SQLite honours interrupt() inside such a walk: the step returns (sqlite3.OperationalError, "interrupted"),
# and the tool's stop handler, already due, answers the stop. The thread holds the stop signals in its own mask, so that they reach the main
# thread. A carrier makes one watch, SqliteWatch(deadline) (a callable that returns the time.monotonic() deadline or None, read on every
# tick, so a deadline that moves is followed; or a number; or None for the stop signals only; on_interrupt(why), when given, is called in the
# watch's thread just before it interrupts, so that a carrier whose progress handler names the reason sees it), watches every connection it opens on
# evidence before its first statement (watch(conn); forget(conn) before it closes one), and closes the watch before it prints its answer
# (close(), idempotent; or `with SqliteWatch(...) as watch:`). interrupted_by is None, "clock" or "stop". set_wakeup_fd works only in the
# main thread: a watch made in another thread ends a statement at the clock only, and `note` says so.
import os
import select
import signal
import threading
import time


class SqliteWatch:
    TICK = 0.25
    STOP_SIGNALS = tuple(getattr(signal, name) for name in ("SIGTERM", "SIGINT", "SIGHUP") if hasattr(signal, name))

    def __init__(self, deadline=None, on_interrupt=None):
        self._deadline = deadline
        self._on_interrupt = on_interrupt
        self._conns = []
        self._lock = threading.Lock()
        self._done = threading.Event()
        self._closed = False
        self.interrupted_by = None                 # "clock" or "stop": the first reason this thread interrupted a statement
        self.note = None                           # a sentence when a stop signal cannot end a statement here
        self._read, self._write = os.pipe()
        os.set_blocking(self._read, False)
        os.set_blocking(self._write, False)
        self._before, self._woken = -1, False
        try:
            self._before = signal.set_wakeup_fd(self._write, warn_on_full_buffer=False)
            self._woken = True
        except (ValueError, OSError) as exc:
            self.note = "a stop signal does not end a statement SQLite runs in C here (%s: the watch was made outside the main thread); the clock does" % type(exc).__name__
        self._thread = threading.Thread(target=self._watch, name="sqlite-watch", daemon=True)
        self._thread.start()

    def deadline(self):
        """The deadline now (time.monotonic()), or None."""
        value = self._deadline
        try:
            value = value() if callable(value) else value
        except Exception:  # noqa: BLE001 - a deadline that cannot be read is no deadline
            return None
        return value if isinstance(value, (int, float)) and not isinstance(value, bool) else None

    def watch(self, conn):
        with self._lock:
            if conn is not None and not self._closed and all(c is not conn for c in self._conns):
                self._conns.append(conn)
        return conn

    def forget(self, conn):
        with self._lock:
            self._conns = [c for c in self._conns if c is not conn]

    def _interrupt(self, why):
        with self._lock:
            if self._on_interrupt is not None and self._conns:
                try:
                    self._on_interrupt(why)
                except Exception:  # noqa: BLE001 - the reason is the carrier's to keep; the interrupt goes on without it
                    pass
            hit = False
            for conn in self._conns:
                try:
                    conn.interrupt()
                    hit = True
                except Exception:  # noqa: BLE001 - a closed connection has nothing to end
                    pass
            if hit and self.interrupted_by is None:
                self.interrupted_by = why

    def _watch(self):
        try:
            signal.pthread_sigmask(signal.SIG_BLOCK, set(self.STOP_SIGNALS))
        except (AttributeError, ValueError, OSError):
            pass
        while not self._done.is_set():
            deadline = self.deadline()
            left = self.TICK if deadline is None else deadline - time.monotonic()
            if left <= 0:
                self._interrupt("clock")
            try:
                ready = select.select([self._read], [], [], min(max(left, 0.0), self.TICK) or self.TICK)[0]
            except (OSError, ValueError):
                ready = []
            if ready:
                try:
                    woke = os.read(self._read, 256)
                except OSError:
                    woke = b""
                if any(number in self.STOP_SIGNALS for number in woke):
                    self._interrupt("stop")

    def close(self):
        """Ends the thread and gives the wake-up pipe back, before the answer is printed."""
        with self._lock:
            if self._closed:
                return
            self._closed = True
            self._conns = []
        self._done.set()
        self._thread.join(timeout=2)
        if self._woken:
            try:
                signal.set_wakeup_fd(self._before)
            except (ValueError, OSError):
                pass
        for fd in (self._read, self._write):
            try:
                os.close(fd)
            except OSError:
                pass

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        self.close()
        return False
# END SHARED SQLITE WATCH


def main():
    install_signal_handlers(_stopped)
    try:
        obj = json.load(sys.stdin)
    except (ValueError, RecursionError) as exc:
        say({"ok": False, "error": "arguments are not valid JSON", "reason": str(exc)}, 1)
    if not isinstance(obj, dict):
        say({"ok": False, "error": "arguments are a JSON object"}, 1)
    write_values = obj.get("write_values", False)
    if not isinstance(write_values, bool):
        say({"ok": False, "error": "write_values must be true or false"}, 1)
    wanted_keys = ("db_path", "table") if write_values else ("db_path", "sql")
    missing = [k for k in wanted_keys if not isinstance(obj.get(k), str) or not obj.get(k)]
    if missing:
        say({"ok": False, "error": "need " + " and ".join(missing),
             "params": ["db_path", "table", "columns", "rowid_from", "rowid_to", "write_values", "limit"] if write_values else ["db_path", "sql", "csv", "limit"]}, 1)
    if write_values:
        VALUES_MODE[0] = True
        if "sql" in obj:
            say({"ok": False, "error": "write_values takes table (and columns, rowid_from, rowid_to), not sql: a WHERE, LIKE, JOIN or any "
                                       "expression over a column whose values are withheld would confirm a guess, one call at a time. The mode "
                                       "exports whole rows of one table and takes no filter; a rowid range is offered only where the rowid is no column's "
                                       "value. For a query over values you may see, leave write_values out.", "write_values": "refused"}, 1)
    else:
        stray = [k for k in VALUES_PARAMS if k in obj]
        if stray:
            say({"ok": False, "error": "%s %s to write_values, which writes the values of one table to a sealed file; "
                                       "an ordinary query takes sql" % (", ".join(stray), "belongs" if len(stray) == 1 else "belong")}, 1)
    db = obj["db_path"]
    sql = obj.get("sql", "")
    for name, text in (("db_path", db), ("sql", sql)):
        if "\0" in text:
            say({"ok": False, "error": "%s holds a NUL character" % name}, 1)
        try:
            text.encode("utf-8")
        except UnicodeEncodeError:
            say({"ok": False, "error": "%s is not text that can be written as UTF-8 (it holds a lone surrogate)" % name}, 1)
    csv_mode = obj.get("csv", False)
    if not isinstance(csv_mode, bool):
        say({"ok": False, "error": "csv is true or false (a text such as \"false\" is not false)", "csv": csv_mode}, 1)
    if "readonly" in obj and obj["readonly"] is not True:
        if obj["readonly"] is False:
            say({"ok": False, "error": "readonly=false is not supported: this tool never opens a database for writing. "
                                       "Stage a copy under $OUT and use the sqlite3 module on the copy.", "db_path": db}, 1)
        say({"ok": False, "error": "readonly is true (the only mode this tool has) or left out", "readonly": obj["readonly"]}, 1)
    limit = obj.get("limit", DEFAULT_LIMIT)
    if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= LIMIT_MAX:
        say({"ok": False, "error": "limit is a whole number from 1 to %d" % LIMIT_MAX, "limit": limit}, 1)
    budget = obj.get("max_seconds", BUDGET_SECONDS)
    if not isinstance(budget, int) or isinstance(budget, bool) or not 1 <= budget <= BUDGET_MAX:
        say({"ok": False, "error": "max_seconds is a whole number from 1 to %d" % BUDGET_MAX, "max_seconds": budget}, 1)
    if len(sql.encode("utf-8")) > SQL_MAX:
        say({"ok": False, "error": "sql is longer than %d bytes" % SQL_MAX}, 1)
    if "apply_wal" in obj:
        say({"ok": False, "error": "apply_wal is not a parameter of sqlite_query, which opens the file it is given read-only and immutable and never applies a WAL. "
                                   "Run sqlite_snapshot on the database: it copies the set (database, -wal, -shm, -journal) with hashes and has SQLite apply the WAL "
                                   "in the copy, and then give this tool the snapshot's directory or its `database` as db_path.", "db_path": db}, 1)
    refusal = values_refusal() if write_values else None
    if refusal:
        say({"ok": False, "error": refusal, "tool": TOOL, "write_values": "refused", "written": False}, 1)
    if not os.path.exists(db):
        say({"ok": False, "error": "database not found", "db_path": db}, 1)
    given = db
    db, snap = find_snapshot(given)
    if not os.path.isfile(db):
        say({"ok": False, "error": "db_path is not a regular file", "db_path": given}, 1)
    size = os.path.getsize(db)
    if size == 0:
        say({"ok": False, "error": "the file is empty (0 bytes): it holds no database", "db_path": db}, 1)
    # sqlite says only "file is not a database" for anything else, and the sixth CTF round's agents met it on
    # Element's SQLCipher events.db without learning why. The first page says what it can: a SQLite file starts
    # with its magic; a file that does not is random from byte 0 or another format. Entropy measures randomness
    # and identifies nothing: encryption is one explanation, compression and another encrypted container others.
    with open_regular(db) as fh:
        page = fh.read(4096)
    if not page.startswith(b"SQLite format 3\x00"):
        e = entropy(page)
        # In values mode the caller has said the file holds secrets: its first bytes are not printed.
        head = {"write_values": "nothing was written"} if write_values else {"header_hex": page[:16].hex()}
        say({"ok": False, "error": "not a SQLite file: its first bytes are not the SQLite magic", "db_path": db,
             **head, "first_page_entropy_bits_per_byte": round(e, 3),
             "reading": ("random-looking from the first byte (high entropy), and not identified: an encrypted database (SQLCipher "
                         "or an app's own) is one explanation, compressed or otherwise encoded data another; no query runs without "
                         "knowing which" if e > 7.5 else "another format: identify it from its header (file_type)")}, 1)

    side = sidecars(db)
    status = snapshot_status(side)
    if snap:
        note = snapshot_note(snap, side)
        status = note if snap["queried"].startswith("applied") else note + " " + status
    if write_values:
        for s in side:
            s["name"] = scrub(cell(s["name"]))
        values_mode(obj, given, db, size, side, scrub(status), snap, limit, budget, csv_mode)
    # immutable=1 opens a database on a read-only mount, where mode=ro alone cannot create a -shm; the path is
    # percent-encoded because a "#" or "?" in it would end the name early.
    uri = "file:%s?mode=ro&immutable=1" % urllib.parse.quote(db)
    stmts = statements(sql)
    if not stmts:
        say({"ok": False, "error": "sql holds no statement"}, 1)
    results, started = [], time.monotonic()
    try:
        conn = connect_checked(db, uri)
    except sqlite3.Error as exc:
        say({"ok": False, "error": "cannot open the database: %s" % exc, "db_path": db}, 1)
    watch = SqliteWatch(started + budget)     # the budget and a stop end a statement SQLite runs in C, where the progress handler is not called (SQLITE WATCH)
    watch.watch(conn)
    conn.text_factory = text_factory
    value_limit = "%d bytes" % VALUE_MAX
    if hasattr(conn, "setlimit") and hasattr(sqlite3, "SQLITE_LIMIT_LENGTH"):
        conn.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, VALUE_MAX)
    else:
        value_limit = "not enforced (Python before 3.11 has no setlimit)"
    conn.set_authorizer(authorizer)
    conn.set_progress_handler(lambda: 1 if time.monotonic() - started > budget else 0, 20000)
    base = {"tool": TOOL, "db_path": given, "database_bytes": size, "sidecars": side, "snapshot_status": status,
            "sqlite_library": sqlite3.sqlite_version, "opened": "read-only, immutable, through an authorizer that allows reading only", "value_limit": value_limit}
    if size <= HASH_MAX:
        base["database_sha256"] = sha256_file(db)
    else:
        base["database_sha256"] = None
        base["hashing"] = "skipped: the file is larger than %d bytes; the run's own record has its sha256" % HASH_MAX
    if db != given:
        base["database_opened"] = db
    if snap:
        snap["file_matches_recorded_sha256"] = (base["database_sha256"] == snap["recorded_sha256"]) if base["database_sha256"] and snap["recorded_sha256"] else None
        if snap["file_matches_recorded_sha256"] is False:
            base["snapshot_status"] = "THE FILE QUERIED IS NOT THE ONE THE SNAPSHOT RECORDED (its sha256 differs from the receipt's): it was changed after the snapshot, or the receipt belongs to another file. " + base["snapshot_status"]
        base["snapshot"] = snap
    failure = None
    for i, stmt in enumerate(stmts):
        word = first_word(stmt)
        if word not in LEADING:
            failure = {"error": "statement refused: this tool reads; a %s statement is not allowed" % (word.upper() or "?"), "statement": stmt}
            break
        rows = None
        failure_kind = None
        try:
            cur = conn.execute(stmt)
            columns = [d[0] for d in (cur.description or [])]
            rows = Rows(i, [db, size, stmt, limit], columns, limit)
            for r in cur:                    # a row at a time: a fetch of many would hold many large values at once
                rows.add(r)
        except (sqlite3.Error, ValueError, UnicodeError, OverflowError, MemoryError) as exc:
            # Decided on sqlite's code, not its message, which can quote a value (sqlite_code).
            code = sqlite_code(exc)
            msg = str(exc)
            if code == SQLITE_AUTH or refused_function(exc):
                msg = "statement refused: it is not a plain read (%s)" % msg
            elif code == SQLITE_TOOBIG:
                msg = ("a value or row in this result is longer than %d bytes, which this tool will not read into memory (sqlite: %s): select its length(), "
                       "or a piece of it with substr(), hex(substr(...)) or a range, in several queries" % (VALUE_MAX, msg))
                failure_kind = "value_too_long"
            elif code == SQLITE_INTERRUPT:
                msg = "stopped at the %d-second time budget; the rows before it are in rows_file when there is one" % budget
            elif isinstance(exc, MemoryError):
                msg = "out of memory reading a row"
            failure = {"error": msg, "statement": stmt}
            if failure_kind:
                failure["reason"] = failure_kind
            if code == SQLITE_INTERRUPT:
                failure["timed_out"] = True
            if rows is not None and rows.total:
                # What was read before the stop is kept and named, not dropped with the file half written.
                failure["rows_read_before_the_stop"] = rows.finish()
                failure["rows_read_before_the_stop"]["note"] = "the rows up to the stop, not the result of the statement"
                failure["rows_read_before_the_stop"]["rows"] = rows.page
            break
        info = rows.finish()
        part = {"statement": stmt, "columns": columns, **info, "rows": rows.page,
                "stdout": render(rows, columns, csv_mode)}
        results.append(part)
    watch.close()
    conn.close()

    out = dict(base)
    if failure:
        out.update({"ok": False, "returncode": 1, "stdout": "", "stderr": failure["error"], **failure, "complete": False})
        if results:
            out["completed_statements"] = results
        say(out, 1)
    # A page that is not the whole result is complete only when the file that holds the whole was written to its end.
    whole = not any(r.get("truncated") and (r.get("rows_file_error") or r.get("rows_file_stopped_at_row")) for r in results)
    out.update({"ok": True, "returncode": 0, "stderr": "", "complete": whole})
    if len(results) == 1:
        out.update(results[0])
    else:
        out["results"] = results
        out["stdout"] = "".join(r["stdout"] for r in results)
    if any(r.get("truncated") for r in results):
        out["truncated"] = True
        out["note"] = "an inline page is not the result: the whole of it is in rows_file; read it to the end before concluding"
    print_answer(answer_status(out))


if __name__ == "__main__":
    exit_code = 0
    try:
        try:
            main()
        except RecursionError:
            say({"ok": False, "error": "internal error: the arguments or the data nest too deeply to read"}, 1)
        except Exception as exc:
            hold_stop_signals(quietly=True)
            # An error nobody expected is an answer too: its class only, since its message can quote what was read.
            say({"ok": False, "error": "internal error: %s" % type(exc).__name__}, 1)
    except SystemExit as stop:
        exit_code = _code(stop)
    _leave(exit_code)
