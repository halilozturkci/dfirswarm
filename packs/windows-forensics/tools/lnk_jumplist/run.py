#!/usr/bin/env python3
"""Read shell links and jump lists as one set of rows: where each structure sits, what it decodes to, and whether it holds together.

An adapter, not a new decoder. A shell link is decoded by this pack's lnk_parse, the DestList stream of a jump list by this
pack's jumplist, a link can be read again by liblnk's `lnkinfo` as an independent reader, and a DestList by Eric Zimmerman's `JLECmd` (through
dotnet) where it is installed; what this tool adds is the part those do not do: it reads the OLE compound file a jump list is stored in (MS-CFB, with the standard library only, so olefile
is not needed) and says where every stream sits in the file, whether the container is consistent, which DestList entry names
which stream, and which entries have no stream and which streams no entry. The rows are JSON Lines, the whole of them kept in a
file the answer names.

Inputs: a shell link (.lnk), an automaticDestinations-ms (a compound file with a DestList stream and a link in each other
stream), a customDestinations-ms (no container: link structures one after another, carved by their 20-byte header, each marked
carved and the container not parsed), or a directory of them (walked, links not followed; a file of another kind is counted,
not read). A file is classified by its first bytes, not its name, when it is named as the path; in a directory by its name.

Rows (`row`): file, container, stream, destlist_entry, link. Every offset of a link's own record (a string's offset, a block's
place) is from the start of that link structure; `container` / `file_offset` and `extents` say where the structure sits in the file.
Each link row has `integrity`: structure_complete, lnk_parse's problems, and what `lnkinfo` says (time, size, volume, target and
label compared field by field, or why it was not run). status is complete only when no row is incomplete, no container problem is
named, no independent read disagrees, nothing was left unread, and the tool's own clock did not run out.

JLECmd reads each jump list's DestList again (once per file, in this tool's process group, under this tool's clock and an output cap, its CSV in a directory under the
output that is removed afterwards) and the two are compared field by field: the entry count, and per entry the path, the access time, the pin state and the application id.
Each DestList entry row has `integrity.jlecmd`: agree, disagree or not_run. A disagreement makes the status partial; a JLECmd that is absent or fails is not_run, said, and
never agree.

The container is checked, not only read: the header, the DIFAT (a FAT sector named twice or outside the file, more of them than a file of
this size can need), the FAT marks of the FAT and DIFAT sectors, the directory (name lengths, object types, a tree that loops, names an entry
twice or an unallocated one, an allocated entry the tree never reaches) and every chain. Each sector is held by one chain: a second chain
that enters it is not followed further, and its row says where it stops, so the work is linear in the sectors of the file. A DestList
entry that names a stream that is not a link is a container problem; so is a container that holds streams and no DestList.

SENSITIVE OUTPUT. A link's arguments, its strings, and the text of a path-like field with the shape of a secret are handled as
lnk_parse handles them: not in the answer; `write_strings: true`, in a job run as secret output, writes them to a file with
mode 0600 under a finding id the rows cite. Refused anywhere else, before anything is made.
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


import array
import bisect
import hashlib
import importlib.util
import json
import os
import re
import shutil
import signal
import stat
import struct
import subprocess
import sys
import tempfile
import time
from pathlib import Path

PARSER = "lnk_jumplist/3"
LNK_MAGIC = bytes.fromhex("4c0000000114020000000000c000000000000046")
OLE_MAGIC = bytes.fromhex("d0cf11e0a1b11ae1")
MAX_LNK_BYTES = 64 << 20          # a link past this is not read whole: it is named and not parsed
MAX_STREAM_BYTES = 32 << 20       # the most of one container stream that is read (the same bound jumplist uses)
MAX_DESTLIST_BYTES = 64 << 20
MAX_DIR_ENTRIES = 100_000
MAX_EXTENTS_SHOWN = 32
DEFAULT_SECONDS = 100
MAX_SECONDS = 110
DEFAULT_FILES = 20_000
LNKINFO_MAX = 400                 # links read again by lnkinfo in one run
JLECMD_MAX = 200                  # jump lists read again by JLECmd in one run (one dotnet start each)
JLECMD_SECONDS = 30               # the longest one JLECmd run is given
JLECMD_MARGIN = 6                 # seconds of the tool's own clock kept back from every JLECmd run, for ending it and for the answer
JLECMD_BYTES = 32 << 20           # the most any one file JLECmd writes may hold (the kernel enforces it); a file that reaches it is not read
BLOCK = 1 << 20

# Lossless paging (the same in every library tool that pages): the page an
# agent reads stays small, and when there are more rows the whole result is
# written as JSON Lines under work/<agent>/tool-output and named.
import hashlib


class LosslessPage:
    def __init__(self, tool: str, key: object, limit: int):
        if isinstance(limit, bool) or not isinstance(limit, int) or limit < 1:
            raise ValueError("limit must be a positive integer")
        self.tool = re.sub(r"[^A-Za-z0-9_.-]", "_", tool)
        self.limit = limit
        self.page: list[object] = []
        self.total = 0
        self._out = None
        self._tmp: Path | None = None
        digest = hashlib.sha256(
            json.dumps(key, sort_keys=True, default=str).encode("utf-8")
        ).hexdigest()[:16]
        name = f"{self.tool}-{digest}.jsonl"
        job, out = os.environ.get("JOB_ID"), os.environ.get("OUT")
        if job and out:
            # In a job only $OUT is written, and it is sealed as the job's
            # output: the whole result is cited from there.
            self.path = Path(out) / "tool-output" / name
            self.shown = "store/jobs/%s/out/tool-output/%s" % (re.sub(r"[^A-Za-z0-9_.-]", "_", job), name)
        else:
            agent = re.sub(
                r"[^A-Za-z0-9_.-]", "_", os.environ.get("AGENT_ID") or "tool"
            )
            self.path = Path("work") / agent / "tool-output" / name
            self.shown = str(self.path)

    def _cannot_write(self, exc: BaseException) -> None:
        """The whole result cannot be kept: say so as JSON and stop, never a traceback."""
        import sys as _sys
        # The hidden temp file goes first: a page that cannot be written leaves nothing behind (a full disk, a quota).
        out, self._out = self._out, None
        try:
            if out is not None:
                out.close()
        except BaseException:
            pass
        try:
            if self._tmp is not None:
                os.unlink(self._tmp)
        except OSError:
            pass
        _sys.stdout.write(json.dumps({
            "error": "the whole result (%d rows so far) cannot be written to %s: %s. Outside a job the place is your own "
                     "work/<your id>/ directory; in a job it is $OUT." % (self.total, self.shown, exc),
            "status": "failed",
        }) + "\n")
        _sys.exit(1)

    def _write(self, row: object) -> None:
        assert self._out is not None
        text = json.dumps(row, ensure_ascii=False, default=str)
        try:
            text.encode("utf-8")
        except UnicodeEncodeError:
            # A lone surrogate (a file name that is not UTF-8): escape it, lose nothing.
            text = json.dumps(row, ensure_ascii=True, default=str)
        try:
            self._out.write(text)
            self._out.write("\n")
        except OSError as exc:
            self._cannot_write(exc)

    def add(self, row: object) -> None:
        self.total += 1
        if len(self.page) < self.limit:
            self.page.append(row)
            return
        if self._out is None:
            try:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                fd, name = tempfile.mkstemp(
                    dir=self.path.parent, prefix=f".{self.path.name}-"
                )
                self._tmp = Path(name)
                self._out = os.fdopen(fd, "w", encoding="utf-8")
            except OSError as exc:
                self._cannot_write(exc)
            for kept in self.page:
                self._write(kept)
        self._write(row)

    def finish(self) -> dict:
        result = {
            "matched": self.total,
            "returned": len(self.page),
            "truncated": self.total > len(self.page),
        }
        if self._out is not None:
            try:
                self._out.flush()
                os.fsync(self._out.fileno())
                self._out.close()
                assert self._tmp is not None
                os.replace(self._tmp, self.path)
            except OSError as exc:
                self._cannot_write(exc)
            result["all_results"] = self.shown
            result["all_results_format"] = "JSON Lines, one complete result per line"
        return result

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


# BEGIN SHARED PAGE
# The same text is in every windows-forensics tool that pages through LosslessPage (held equal by a windows-forensics test): LosslessPage replaces a file of the
# same name; this one places its finished file with place_without_replacing, and registers itself so that a stop can remove its temporary file.
PAGES = []


class NoReplacePage(LosslessPage):
    """LosslessPage whose finished file is placed without replacing an earlier file of the same name (a rerun with other limits, or one
    the time limit stopped, must not leave a smaller file where a larger one was)."""

    def __init__(self, tool, key, limit):
        super().__init__(tool, key, limit)
        PAGES.append(self)

    def add(self, row: object, *rest) -> object:
        """The hidden temporary file is made, and registered in `_tmp`, with the stop signals held: a stop that landed between mkstemp and the
        registration found no file to remove and left a hidden one behind (the SIGTERM case of tests/pack-windows-forensics-fs-contract.test.ts, 1 run
        in many on a loaded Mac). A signal that comes in meanwhile waits and is answered, by the handler that removes the file, as soon as the
        registration is in."""
        if self._out is not None or len(self.page) < self.limit:
            return super().add(row, *rest)
        before = None
        try:
            before = signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGTERM, signal.SIGINT, signal.SIGHUP})
        except (AttributeError, ValueError, OSError):
            pass
        try:
            return super().add(row, *rest)
        finally:
            if before is not None:
                signal.pthread_sigmask(signal.SIG_SETMASK, before)

    def finish(self) -> dict:
        result = {"matched": self.total, "returned": len(self.page), "truncated": self.total > len(self.page)}
        if self._out is not None:
            try:
                self._out.flush()
                os.fsync(self._out.fileno())
                self._out.close()
                assert self._tmp is not None
                placed = place_without_replacing(self._tmp, self.path)
            except OSError as exc:
                self._cannot_write(exc)
            self._tmp = None
            self.path = placed
            self.shown = self.shown[: len(self.shown) - len(Path(self.shown).name)] + placed.name
            result["all_results"] = self.shown
            result["all_results_format"] = "JSON Lines, one complete result per line"
        return result
# END SHARED PAGE


# BEGIN SHARED PROCESS
# The same text is in every windows-forensics tool and recipe that starts a program (and in any other pack's tool that copies it);
# tests/pack-windows-forensics-process.test.ts holds the copies equal. A program a tool runs is started in THIS tool's process group, never in a session of its own: the
# harness ends a tool that runs too long, or is aborted, by killing the tool's group (process.kill(-pid, SIGKILL)), and a
# program in a group of its own goes on writing after the tool is gone. On Linux the kernel is also asked to kill it if the
# tool dies. The tool's own deadline kills the program and what it started by walking the process tree, and SIGTERM, SIGINT
# and SIGHUP do the same and then give the tool a last word. Only what is
# below a program this tool started and has not yet waited for is ever signalled: the walk starts at that program's pid
# and nowhere else, and a program that has been waited for (its pid may be another process's by now) is left alone. The
# walk is bounded (MAX_ROUNDS and WALK_SECONDS, below). A stop signal is the one case that reaches further: it also
# ends everything below the tool itself (a program that was forked a moment before it was entered in ACTIVE is among it) and what
# the tool started and lost (reap_orphans): a process that was seen below the tool, in the tool's own group, and whose parent has since
# ended. Nothing else is ever ended: a process the tool never saw in its tree (the next stage of a pipeline the tool heads, a process a
# launcher put in the group) is left alone, whoever leads the group. A program that has ended while something it started still
# holds its pipes does not hold the tool: communicate_bounded gives the pipes PIPE_GRACE seconds (and POST_EXIT_BYTES bytes) and goes on without them. (In the
# windows lineage only the windows-artefacts recipe and lnk_jumplist call it; the lineage is one text, so the others carry it unused.)
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


def wait_for(proc, seconds):
    """(exit code, timed out): wait for the program for at most `seconds`; at the deadline it and what it started are killed."""
    ACTIVE.append(proc)
    try:
        try:
            return proc.wait(timeout=seconds), False
        except subprocess.TimeoutExpired:
            kill_tree(proc)
            return proc.wait(), True
    finally:
        if proc in ACTIVE:
            ACTIVE.remove(proc)


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
    answer_a_stop(signum)
    os._exit(128 + signum)


def install_signal_handlers():
    for signum in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(signum, _on_signal)
# END SHARED PROCESS


# ---- helpers ------------------------------------------------------------------------------------------------------------------------

def fail(message, **extra):
    hold_stop_signals()
    if hasattr(signal, "pthread_sigmask"):
        signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGTERM, signal.SIGINT, signal.SIGHUP})     # one document: the stop handlers may not be in yet (a refusal can come before main() installs them), and one that is in would write a second, false, document after this one; a stop that arrives while this is written waits, and the tool leaves with it
    print(json.dumps({"ok": False, "error": message, "status": "failed", "status_basis": "the tool stopped with an error (see error); nothing was read", **extra}))
    sys.exit(1)


def describe(exc):
    if isinstance(exc, OSError):
        return "%s: %s" % (type(exc).__name__, exc.strerror or exc)
    return "%s: %s" % (type(exc).__name__, exc)


CLOCK = {"deadline": None}
TEMPS = []
TEMP_DIRS = []                    # the directories JLECmd writes into; each is removed when its run ends, or by the last word


def out_of_time():
    return CLOCK["deadline"] is not None and time.monotonic() > CLOCK["deadline"]


def forget_temps():
    for page in list(PAGES):
        tmp = getattr(page, "_tmp", None)
        if tmp is not None:
            try:
                os.unlink(tmp)
            except OSError:
                pass
    for path in list(TEMPS):
        try:
            os.unlink(path)
        except OSError:
            pass
        TEMPS.remove(path)
    for path in list(TEMP_DIRS):
        shutil.rmtree(path, ignore_errors=True)
        TEMP_DIRS.remove(path)


def shown_path(path):
    job, out = os.environ.get("JOB_ID"), os.environ.get("OUT")
    path = Path(path)
    if job and out:
        try:
            return "store/jobs/%s/out/%s" % (re.sub(r"[^A-Za-z0-9_.-]", "_", job), path.resolve().relative_to(Path(out).resolve()))
        except ValueError:
            return str(path)
    try:
        return str(path.resolve().relative_to(Path.cwd().resolve()))
    except ValueError:
        return str(path)


def output_directory(identity):
    job, out = os.environ.get("JOB_ID"), os.environ.get("OUT")
    name = "lnk_jumplist-" + identity
    if job and out:
        base = Path(out)
    else:
        agent = re.sub(r"[^A-Za-z0-9_.-]", "_", os.environ.get("AGENT_ID") or "tool")
        base = Path.cwd() / "work" / agent
    return base / name


class FilePage(NoReplacePage):
    """A paging file placed in the tool's own output directory under a fixed name, never replacing an earlier file."""

    def __init__(self, directory, name, key, limit):
        super().__init__("lnk_jumplist", key, limit)
        self.path = directory / name
        self.shown = shown_path(self.path)

    def finish(self):
        if self._out is None and self.total:
            # the whole result is always a file the answer names, even when it fits in the inline page
            try:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                fd, name = tempfile.mkstemp(dir=self.path.parent, prefix=".%s-" % self.path.name)
                self._tmp = Path(name)
                self._out = os.fdopen(fd, "w", encoding="utf-8")
            except OSError as exc:
                self._cannot_write(exc)
            for kept in self.page:
                self._write(kept)
        result = super().finish()
        if result.get("all_results"):
            result["all_results"] = shown_path(self.path)
        return result


def load_sibling(name):
    """This pack's own tool, loaded as a module so that its decoder is used in this process: the pack is read-only code, installed beside this tool."""
    path = Path(__file__).resolve().parent.parent / name / "run.py"
    spec = importlib.util.spec_from_file_location("dfir_windows_" + name, str(path))
    module = importlib.util.module_from_spec(spec)
    # A sibling carries the windows STOP block, which installs its own signal handlers when the module runs. Those would replace this tool's
    # (its last word ends lnkinfo and removes its temporary files), so the stop signals are held while the sibling loads and this tool's
    # handlers are put back before they are let through: a signal that came meanwhile is then answered by this tool's own last word.
    stop_signals = (signal.SIGTERM, signal.SIGINT, signal.SIGHUP)
    ours = {s: signal.getsignal(s) for s in stop_signals}
    try:
        held_before = signal.pthread_sigmask(signal.SIG_BLOCK, set(stop_signals))
    except (AttributeError, ValueError, OSError):
        held_before = None
    try:
        spec.loader.exec_module(module)
    finally:
        for s, handler in ours.items():
            signal.signal(s, handler)
        if held_before is not None:
            signal.pthread_sigmask(signal.SIG_SETMASK, held_before)
    return module


def ft_iso(value):
    if not value:
        return None
    try:
        import datetime
        whole, ticks = divmod(int(value), 10_000_000)
        return (datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc) + datetime.timedelta(seconds=whole)).strftime("%Y-%m-%dT%H:%M:%S") + ".%07dZ" % ticks
    except (OverflowError, ValueError, TypeError):
        return None


# ---- the compound file (MS-CFB), with the standard library -------------------------------------------------------------------------

FREESECT, ENDOFCHAIN, FATSECT, DIFSECT = 0xFFFFFFFF, 0xFFFFFFFE, 0xFFFFFFFD, 0xFFFFFFFC
NOSTREAM = 0xFFFFFFFF
OWNER_MAX_SECTORS = 1 << 26          # past this many sectors (a 32 GiB file) the sectors' owners are not tracked, and the container says so
MARKERS = {FREESECT: "free", FATSECT: "FAT", DIFSECT: "DIFAT"}


class CfbError(Exception):
    pass


class CfbTime(Exception):
    """The tool's own time limit was reached while a container was being read."""


class Problems:
    """What is wrong with a container, by kind: the first example of a kind is kept whole and the others are counted, so a damaged file that
    repeats one fault a million times is one line with a count and not a million lines. The streams' own rows carry their own faults."""

    def __init__(self):
        self.kinds = {}

    def add(self, kind, text):
        item = self.kinds.get(kind)
        if item is None:
            self.kinds[kind] = [text, 1]
        else:
            item[1] += 1

    def lines(self):
        return [text if n == 1 else "%s (and %d more of this kind)" % (text, n - 1) for text, n in self.kinds.values()]

    def total(self):
        return sum(n for _t, n in self.kinds.values())


def mark_text(marker):
    return MARKERS.get(marker, "unknown")


class Cfb:
    """The directory and sector chains of a compound file, read in sectors (never the file whole). `problems` collects what is inconsistent;
    a header that is not a compound file's raises CfbError.

    Every sector that something holds (the FAT, the DIFAT, the directory, the mini FAT, the mini stream, each stream) is claimed once in an owner
    table, so a chain that loops, a chain that enters another chain and a stream that shares a sector are found by the same lookup and a chain is
    followed at most once: the work is linear in the sectors of the file however many streams name the same chain. A chain that enters sectors another
    holds is not followed further (its extents stop there and the row says where it goes on)."""

    def __init__(self, fh, size):
        self.fh, self.size, self.found = fh, size, Problems()
        head = self._read(0, 512)
        if len(head) < 512 or head[:8] != OLE_MAGIC:
            raise CfbError("not a compound file: the 8-byte signature is missing")
        major, = struct.unpack_from("<H", head, 0x1A)
        order, shift, mshift = struct.unpack_from("<HHH", head, 0x1C)
        if order != 0xFFFE:
            raise CfbError("the byte order mark is 0x%04x, not 0xFFFE" % order)
        if (major, shift) not in ((3, 9), (4, 12)) or mshift != 6:
            raise CfbError("major version %d with sector shift %d and mini sector shift %d is not a layout this reader knows (3/9/6 or 4/12/6)" % (major, shift, mshift))
        self.major, self.ss, self.mini_ss = major, 1 << shift, 64
        self.per = self.ss // 4
        (self.n_fat, self.dir_start, _txn, self.cutoff, self.minifat_start, self.n_minifat, self.difat_start, self.n_difat) = struct.unpack_from("<IIIIIIII", head, 0x2C)
        self.sectors = max(-(-(size - self.ss) // self.ss), 0)       # the header takes the first sector-sized slot
        if size % self.ss:
            self.flag("short", "the file is %d bytes, not a whole number of %d-byte sectors (the last sector is short)" % (size, self.ss))
        n_dir_sectors = struct.unpack_from("<I", head, 0x28)[0]
        if major == 3 and n_dir_sectors:
            self.flag("header", "the header gives %d directory sectors; a version 3 file keeps zero there" % n_dir_sectors)
        self.n_dir_sectors = n_dir_sectors
        if head[0x22:0x28] != bytes(6):
            self.flag("header", "the reserved bytes of the header (0x22 to 0x27) are not zero")
        if self.cutoff != 4096:
            self.flag("header", "the mini stream cutoff is %d bytes, not the 4096 the specification fixes" % self.cutoff)
        self.labels, self.label_ids = [None], {}
        self.owner = array.array("I", bytes(4 * self.sectors)) if self.sectors <= OWNER_MAX_SECTORS else None
        if self.owner is None:
            self.flag("owners", "the file holds %d sectors: which sector belongs to which chain is not tracked at this size, so a shared sector would not be found" % self.sectors)
        self.fat = array.array("I")
        self._load_fat(head)
        self.mini_owner = None
        self.directory = self._directory()
        self.minifat = self._minifat()
        self.mini_container = None

    @property
    def problems(self):
        return self.found.lines()

    def flag(self, kind, text):
        self.found.add(kind, text)

    def _read(self, offset, length):
        self.fh.seek(offset)
        return self.fh.read(length)

    def _sector(self, n):
        return self._read(self.ss * (n + 1), self.ss).ljust(self.ss, b"\x00")

    def sector_offset(self, n):
        return self.ss * (n + 1)

    def claim(self, sector, key, text):
        """Record that the chain `key` (named `text`) holds `sector`. None when it was free; ("loop", text) when this chain held it already;
        ("shared", text of the other chain) when another did."""
        if self.owner is None or sector >= len(self.owner):
            return None
        label = self.label_ids.get(key)
        if label is None:
            label = self.label_ids[key] = len(self.labels)
            self.labels.append(text)
        held = self.owner[sector]
        if held == 0:
            self.owner[sector] = label
            return None
        return ("loop" if held == label else "shared", self.labels[held])

    def _load_fat(self, head):
        max_fat = -(-self.sectors // self.per)                     # FAT sectors that describe every sector of a file this size
        max_difat = max(-(-(max_fat - 109) // (self.per - 1)), 0)
        listed, difat_sectors, names = [], [], {}                  # the FAT sectors the DIFAT lists (distinct, in order); sector -> first position
        extra = [0]

        def note(position, sector):
            if sector == FREESECT:
                return
            if len(names) >= self.n_fat or len(listed) >= max_fat:
                extra[0] += 1
                return
            if sector in names:
                self.flag("fat-twice", "the DIFAT names FAT sector %d more than once (entries %d and %d)" % (sector, names[sector], position))
                self.fat.extend(array.array("I", [FREESECT]) * self.per)           # its place in the FAT stays, empty
                return
            names[sector] = position
            if sector >= self.sectors:
                self.flag("fat-outside", "a FAT sector (%d) is outside the file" % sector)
                self.fat.extend(array.array("I", [FREESECT]) * self.per)
                return
            listed.append(sector)
            block = array.array("I")
            block.frombytes(self._sector(sector)[: self.ss])
            if sys.byteorder != "little":
                block.byteswap()
            self.fat.extend(block)

        position = 0
        for sector in struct.unpack_from("<109I", head, 0x4C):
            note(position, sector)
            position += 1
        seen, nxt, walked = set(), self.difat_start, 0
        while nxt not in (ENDOFCHAIN, FREESECT) and walked < max(self.n_difat, 0) + 1:
            if nxt in seen or nxt >= self.sectors:
                self.flag("difat", "the DIFAT chain %s (sector %d)" % ("loops" if nxt in seen else "leaves the file", nxt))
                break
            if walked >= max_difat:
                self.flag("difat", "the DIFAT chain is longer than a file of %d sectors can need (%d DIFAT sectors at most); the rest of it is not read" % (self.sectors, max_difat))
                break
            if out_of_time():
                raise CfbTime()
            seen.add(nxt)
            difat_sectors.append(nxt)
            walked += 1
            raw = self._sector(nxt)
            for sector in struct.unpack_from("<%dI" % (self.per - 1), raw, 0):
                note(position, sector)
                position += 1
            nxt = struct.unpack_from("<I", raw, (self.per - 1) * 4)[0]
        if walked != self.n_difat:
            self.flag("difat", "the header declares %d DIFAT sectors and the DIFAT chain holds %d" % (self.n_difat, walked))
        if extra[0]:
            self.flag("fat-count", "the DIFAT names %d more FAT sector(s) than the header declares (%d) or than a file of %d sectors can need (%d)" % (extra[0], self.n_fat, self.sectors, max_fat))
        if len(names) < self.n_fat:
            self.flag("fat-count", "the header declares %d FAT sectors and the DIFAT names %d" % (self.n_fat, len(names)))
        for sector in listed:
            held = self.claim(sector, ("fat", sector), "the FAT")
            if held:
                self.flag("shared", "FAT sector %d is also held by %s" % (sector, held[1]))
            if sector < len(self.fat) and self.fat[sector] != FATSECT:
                self.flag("fat-mark", "FAT sector %d is not marked as a FAT sector in the FAT (its entry is %s)" % (sector, self._entry_text(self.fat[sector])))
            elif sector >= len(self.fat):
                self.flag("fat-mark", "FAT sector %d lies past the end of the FAT, so it cannot be marked as a FAT sector" % sector)
        for sector in difat_sectors:
            held = self.claim(sector, ("difat", sector), "the DIFAT")
            if held:
                self.flag("shared", "DIFAT sector %d is also held by %s" % (sector, held[1]))
            if sector < len(self.fat) and self.fat[sector] != DIFSECT:
                self.flag("fat-mark", "DIFAT sector %d is not marked as a DIFAT sector in the FAT (its entry is %s)" % (sector, self._entry_text(self.fat[sector])))
        if self.fat.count(FATSECT) != len(listed):
            self.flag("fat-mark", "the FAT marks %d sectors as FAT sectors and the DIFAT names %d" % (self.fat.count(FATSECT), len(listed)))
        if self.fat.count(DIFSECT) != len(difat_sectors):
            self.flag("fat-mark", "the FAT marks %d sectors as DIFAT sectors and the DIFAT chain holds %d" % (self.fat.count(DIFSECT), len(difat_sectors)))
        if len(self.fat) < self.sectors:
            self.flag("fat-short", "the FAT describes %d sectors and the file holds %d" % (len(self.fat), self.sectors))

    @staticmethod
    def _entry_text(value):
        return {FREESECT: "free", ENDOFCHAIN: "end of chain", FATSECT: "FAT", DIFSECT: "DIFAT"}.get(value, "sector %d" % value)

    def follow(self, start, key, text, stop, limit=None):
        """The sectors of one chain, one at a time. `stop` receives why the chain ended: ("end",), ("marker", marker), ("outside", sector, in_fat),
        ("loop", sector), ("shared", sector, other), ("limit",) when the chain goes on past `limit` sectors, or ("time",)."""
        n, steps, fat = start, 0, self.fat
        while True:
            if n == ENDOFCHAIN:
                stop.append(("end",))
                return
            if n in (FREESECT, FATSECT, DIFSECT):
                stop.append(("marker", n))
                return
            if n >= len(fat) or n >= self.sectors:
                stop.append(("outside", n, n < len(fat)))
                return
            if limit is not None and steps >= limit:
                label = self.label_ids.get(key)
                stop.append(("loop", n, text) if label is not None and self.owner is not None and self.owner[n] == label else ("limit",))
                return
            if steps & 0x3FFF == 0x3FFF and out_of_time():
                raise CfbTime()
            held = self.claim(n, key, text)
            if held is not None:
                stop.append((held[0], n, held[1]))
                return
            yield n
            steps += 1
            n = fat[n]

    def stop_text(self, stop, what):
        """The sentence for a chain that did not end cleanly, or None."""
        kind = stop[0]
        if kind == "marker":
            return "%s: its chain reaches a %s sector" % (what, mark_text(stop[1]))
        if kind == "outside":
            return "%s: its chain reaches sector %d, outside %s" % (what, stop[1], "the file" if stop[2] else "the FAT")
        if kind == "loop":
            return "%s: its sector chain loops back to sector %d" % (what, stop[1])
        if kind == "shared":
            return "%s shares sector %d with %s" % (what, stop[1], stop[2])
        return None

    def chain(self, start, key, what):
        """The sectors of a whole chain as a list (the directory, the mini FAT, the mini stream), and what is wrong with it."""
        out, stop = [], []
        if start in (ENDOFCHAIN, FREESECT):
            return out
        out.extend(self.follow(start, key, what, stop))
        text = self.stop_text(stop[0], what)
        if text:
            self.flag("chain-" + stop[0][0], text)
        return out

    def _directory(self):
        entries = []
        sectors = self.chain(self.dir_start, ("dir",), "the directory")
        if self.major == 4 and self.n_dir_sectors != len(sectors):
            self.flag("header", "the header gives %d directory sectors and the directory chain holds %d" % (self.n_dir_sectors, len(sectors)))
        for s in sectors:
            raw = self._sector(s)
            for i in range(self.ss // 128):
                if len(entries) >= MAX_DIR_ENTRIES:
                    self.flag("dir-limit", "the directory holds more than %d entries; the rest are not read" % MAX_DIR_ENTRIES)
                    return entries
                rec = raw[i * 128:(i + 1) * 128]
                nlen = struct.unpack_from("<H", rec, 64)[0]
                kind = rec[66]
                name = rec[: max(min(nlen, 64) - 2, 0)].decode("utf-16-le", "replace") if kind else ""
                left, right, child = struct.unpack_from("<III", rec, 68)
                start = struct.unpack_from("<I", rec, 116)[0]
                size = struct.unpack_from("<Q", rec, 120)[0]
                if self.major == 3:
                    if size >> 32 and kind in (2, 5):
                        self.flag("dir-size", "directory entry %d (%r) has a size of %d bytes: a version 3 file keeps a size in the low 32 bits and the high 32 bits are zero, so only the low 32 bits (%d) are used"
                                  % (len(entries), name, size, size & 0xFFFFFFFF))
                    size &= 0xFFFFFFFF
                index = len(entries)
                if kind in (1, 2, 5):
                    if nlen < 4 or nlen > 64 or nlen % 2:
                        self.flag("dir-name", "directory entry %d (a %s) has a name length of %d bytes: a name is an even number of bytes from 4 (one character and its end) to 64, so %s"
                                  % (index, {1: "storage", 2: "stream", 5: "root"}[kind], nlen, "the entry has no name that can be read" if nlen < 4 else "its name is cut or damaged"))
                    elif rec[nlen - 2:nlen] != b"\x00\x00":
                        self.flag("dir-name", "directory entry %d (%r) has a name that does not end with its end mark" % (index, name))
                elif kind != 0:
                    self.flag("dir-type", "directory entry %d has the object type %d, which the specification does not define" % (index, kind))
                if kind == 5 and index != 0:
                    self.flag("dir-type", "directory entry %d is a second root storage" % index)
                entries.append({"id": index, "name": name, "type": kind, "left": left, "right": right, "child": child, "start": start, "size": size})
        return entries

    def _minifat(self):
        if self.minifat_start in (ENDOFCHAIN, FREESECT) or not self.n_minifat:
            return array.array("I")
        out = array.array("I")
        sectors = self.chain(self.minifat_start, ("minifat",), "the mini FAT")
        if len(sectors) != self.n_minifat:
            self.flag("minifat-count", "the header declares %d mini FAT sectors and the chain holds %d" % (self.n_minifat, len(sectors)))
        for s in sectors:
            block = array.array("I")
            block.frombytes(self._sector(s)[: self.ss])
            if sys.byteorder != "little":
                block.byteswap()
            out.extend(block)
        return out

    def streams(self):
        """Every stream entry reached from the root by the red-black tree, with its path; a loop in the tree, a link to an entry that is not allocated and an
        allocated entry the tree never reaches are problems."""
        if not self.directory or self.directory[0]["type"] != 5:
            self.flag("root", "the first directory entry is not the root storage")
            return []
        found, seen, stack = [], {0}, [(self.directory[0]["child"], "")]
        while stack:
            sid, prefix = stack.pop()
            if sid == NOSTREAM:
                continue
            if sid >= len(self.directory) or sid in seen:
                self.flag("tree", "the directory tree %s (entry %d)" % ("loops, or names an entry twice" if sid in seen else "names an entry outside the directory", sid))
                continue
            seen.add(sid)
            e = self.directory[sid]
            if e["type"] == 0:
                self.flag("tree-free", "the directory tree names entry %d, which is not allocated" % sid)
                continue
            if e["type"] not in (1, 2):
                self.flag("tree-type", "the directory tree names entry %d, which is not a storage or a stream (object type %d)" % (sid, e["type"]))
                continue
            stack.append((e["left"], prefix))
            stack.append((e["right"], prefix))
            path = prefix + e["name"]
            if e["type"] == 2:
                if e["child"] != NOSTREAM:
                    self.flag("stream-child", "directory entry %d (stream %r) has a child pointer (%d): a stream has no children, so the tree names an entry twice or names one that is not there" % (sid, e["name"], e["child"]))
                found.append({**e, "path": path})
            elif e["type"] == 1:
                stack.append((e["child"], path + "/"))
        for e in self.directory[1:]:
            if e["type"] in (1, 2) and e["id"] not in seen:
                self.flag("unreachable", "directory entry %d (%r, a %s) is allocated but the directory tree from the root never reaches it" % (e["id"], e["name"], "storage" if e["type"] == 1 else "stream"))
        names = [s["path"].lower() for s in found]
        if len(set(names)) != len(names):
            self.flag("same-name", "two streams have the same name")
        return sorted(found, key=lambda s: s["id"])

    def _container_chain(self):
        if self.mini_container is None:
            root = self.directory[0] if self.directory else None
            self.mini_container = self.chain(root["start"], ("mini",), "the mini stream") if root and root["start"] not in (ENDOFCHAIN, FREESECT) and root["size"] else []
            if root and root["size"] and len(self.mini_container) * self.ss < root["size"]:
                self.flag("mini", "the root entry declares a mini stream of %d bytes and its chain holds %d" % (root["size"], len(self.mini_container) * self.ss))
        return self.mini_container

    def extents(self, entry):
        """([(stream offset, file offset, length)] of a stream, joined where the sectors are neighbours, whether the chain is whole, this stream's own
        problems). The extents are joined as they are found, so a stream of any length holds only its fragments in memory."""
        size = entry["size"]
        label = "stream %r" % entry["name"]
        key = ("stream", entry["id"])
        joined, whole, mine = [], True, []

        def say(kind, text):
            self.flag(kind, text)
            if len(mine) < 5:
                mine.append(text)

        def push(at, off, n):
            if joined and joined[-1][0] + joined[-1][2] == at and joined[-1][1] + joined[-1][2] == off:
                joined[-1] = (joined[-1][0], joined[-1][1], joined[-1][2] + n)
            else:
                joined.append((at, off, n))

        if size == 0:
            return joined, True, mine
        stop = []
        if size < self.cutoff:
            container = self._container_chain()
            if self.mini_owner is None:
                self.mini_owner = array.array("I", bytes(4 * len(self.minifat)))
            need = -(-size // self.mini_ss)
            at, count, n = 0, 0, entry["start"]
            while True:
                if n == ENDOFCHAIN:
                    stop.append(("end",))
                    break
                if n in (FREESECT, FATSECT, DIFSECT) or n >= len(self.minifat):
                    stop.append(("mini-outside", n))
                    break
                if count >= need:
                    stop.append(("mini-loop", n) if self.mini_owner[n] == entry["id"] + 1 else ("limit",))
                    break
                if count & 0x3FFF == 0x3FFF and out_of_time():
                    raise CfbTime()
                held = self.mini_owner[n]
                mark = entry["id"] + 1
                if held:
                    stop.append(("mini-loop" if held == mark else "mini-shared", n, self._stream_name(held - 1)))
                    break
                self.mini_owner[n] = mark
                c, within = divmod(n * self.mini_ss, self.ss)
                if n * self.mini_ss >= self.mini_size():
                    say("mini-past", "%s: mini sector %d is past the end of the mini stream, which the root entry declares as %d bytes" % (label, n, self.mini_size()))
                    whole = False
                    break
                if c >= len(container):
                    say("mini-past", "%s: mini sector %d is past the end of the mini stream" % (label, n))
                    whole = False
                    break
                take = min(self.mini_ss, size - at)
                push(at, self.sector_offset(container[c]) + within, take)
                at += take
                count += 1
                n = self.minifat[n]
            kind = stop[0][0] if stop else "end"
            if kind == "mini-outside":
                say("chain-mini", "%s: its mini sector chain leaves the mini FAT (sector %d)" % (label, stop[0][1]))
            elif kind == "mini-loop":
                say("chain-loop", "%s: its mini sector chain loops back to mini sector %d" % (label, stop[0][1]))
            elif kind == "mini-shared":
                say("shared-mini", "%s shares mini sector %d with %s" % (label, stop[0][1], stop[0][2]))
            elif kind == "limit":
                say("chain-long", "%s: its mini sector chain holds more sectors than its %d bytes need" % (label, size))
            if at < size:
                say("chain-short", "%s declares %d bytes and its mini chain holds %d" % (label, size, at))
                whole = False
        else:
            need = -(-size // self.ss)
            at = 0
            for s in self.follow(entry["start"], key, label, stop, limit=need):
                take = min(self.ss, size - at)
                push(at, self.sector_offset(s), take)
                at += take
            text = self.stop_text(stop[0], label)
            if text:
                say("chain-" + stop[0][0], text)
            elif stop[0][0] == "limit":
                say("chain-long", "%s: its sector chain holds more sectors than its %d bytes need" % (label, size))
            if at < size:
                say("chain-short", "%s declares %d bytes and its chain holds %d" % (label, size, at))
                whole = False
        return joined, whole, mine

    def mini_size(self):
        return self.directory[0]["size"] if self.directory else 0

    def _stream_name(self, entry_id):
        return "stream %r" % self.directory[entry_id]["name"] if 0 <= entry_id < len(self.directory) else "another stream"

    def read(self, extents, limit):
        data = bytearray()
        for _at, off, n in extents:
            if len(data) >= limit:
                break
            data += self._read(off, min(n, limit - len(data)))
        return bytes(data)


def map_range(extents, starts, start, length):
    """Where [start, start + length) of a stream is in the file: [(file offset, bytes)], one piece when it is contiguous. `extents` are in stream order and
    `starts` is their stream offsets, so the first extent that can hold `start` is found by bisection and the walk stops at the end of the range: a stream
    of many fragments costs the fragments a range touches, not all of them, however many ranges are asked."""
    out, end = [], start + length
    i = max(bisect.bisect_right(starts, start) - 1, 0)
    while i < len(extents) and extents[i][0] < end:
        at, off, n = extents[i]
        lo, hi = max(at, start), min(at + n, end)
        if lo < hi:
            out.append((off + lo - at, hi - lo))
        i += 1
    return out


# ---- lnkinfo, the independent reader ---------------------------------------------------------------------------------------------------

MONTHS = {m: i + 1 for i, m in enumerate("Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec".split())}
TIME_LINE = re.compile(r"^([A-Z][a-z]{2}) (\d{1,2}), (\d{4}) (\d\d):(\d\d):(\d\d)\.(\d{9}) UTC$")


def lnkinfo_fields(text):
    fields = {}
    for line in text.splitlines():
        m = re.match(r"^\t([A-Za-z][A-Za-z ]*?)\t+: (.*)$", line)
        if m and m.group(1) not in fields:
            fields[m.group(1)] = m.group(2).strip()
    return fields


def lnkinfo_time(value):
    m = TIME_LINE.match(value or "")
    if not m or m.group(1) not in MONTHS:
        return None
    return "%s-%02d-%02dT%s:%s:%s.%sZ" % (m.group(3), MONTHS[m.group(1)], int(m.group(2)), m.group(4), m.group(5), m.group(6), m.group(7)[:7])


def lnkinfo_run(path, seconds):
    import shutil
    program = shutil.which("lnkinfo")
    if not program:
        return None, "lnkinfo (liblnk-utils) is not in this image"
    try:
        proc = spawn([program, str(path)], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except OSError as exc:
        return None, "lnkinfo could not be started: %s" % describe(exc)
    ACTIVE.append(proc)
    cut_before = PIPE_CUT["cut"]
    try:
        out, _err, timed_out = communicate_bounded(proc, max(1.0, seconds))
    finally:
        if proc in ACTIVE:
            ACTIVE.remove(proc)
    if timed_out:
        return None, "lnkinfo did not answer in %d seconds" % max(1, int(seconds))
    if proc.returncode != 0:
        return None, "lnkinfo exited %d (it could not read the structure)" % proc.returncode
    if PIPE_CUT["cut"] > cut_before:
        # lnkinfo prints on a pipe, so it is not held to the unproven rule; but a process that held the pipe after lnkinfo ended went on writing, and its bytes are mixed into the text
        # that would be compared with lnk_parse: that text is not used (the link keeps lnk_parse's reading, with `ran: false` and this reason) and the answer says so (finish)
        return None, "lnkinfo's pipe was cut at %d bytes (a process that held it after lnkinfo ended went on writing): its output may contain bytes lnkinfo did not write and was not compared" % POST_EXIT_BYTES
    return lnkinfo_fields(out.decode("utf-8", "replace")), None


def compare_lnkinfo(decoded, info):
    """Field by field: what lnk_parse and lnkinfo both say, equal or not. A field one does not print is not compared."""
    checked, differ = [], []

    def same(name, mine, theirs):
        checked.append(name)
        if mine != theirs:
            differ.append({"field": name, "lnk_parse": mine, "lnkinfo": theirs})

    for field, label in (("created", "Creation time"), ("accessed", "Access time"), ("written", "Modification time")):
        theirs = info.get(label)
        if theirs is not None:
            same(field, decoded.get(field), lnkinfo_time(theirs) if not theirs.startswith("Not set") else None)
    if "File size" in info:
        m = re.match(r"(\d+) bytes", info["File size"])
        if m:
            same("file_length", decoded.get("file_length"), int(m.group(1)))
    volume = decoded.get("volume")
    if isinstance(volume, dict):
        if "Drive serial number" in info:
            same("volume.serial_number", str(volume.get("serial_number", "")).lower(), info["Drive serial number"].lower().replace("0x", ""))
        m = re.search(r"\((\d+)\)$", info.get("Drive type", ""))
        if m:
            same("volume.drive_type", volume.get("drive_type"), int(m.group(1)))
        if "Volume label" in info:
            same("volume.label", volume.get("label"), info["Volume label"])
    target = decoded.get("linkinfo_target")
    kind = decoded.get("linkinfo_target_kind")
    if target is not None and kind in ("local", "network"):
        theirs = info.get("Local path" if kind == "local" else "Network path")
        if theirs is not None:
            base = decoded.get("local_base_path") or ""
            suffix = decoded.get("common_path") or ""
            # liblnk puts a separator between the base path and the suffix where the link has none; the specification only joins them.
            ok = theirs == target or (kind == "local" and suffix and not base.endswith("\\") and theirs == base + "\\" + suffix)
            checked.append("target")
            if not ok:
                differ.append({"field": "target", "lnk_parse": target, "lnkinfo": theirs})
    return checked, differ

# ---- JLECmd, the second reader of a DestList ----------------------------------------------------------------------------------------------

JLECMD_COLUMNS = ("EntryNumber", "Path", "LastModified", "PinStatus", "AppId")   # what this tool compares; a CSV without one of them is not compared
JLECMD_TIME = re.compile(r"^(\d{4}-\d\d-\d\d)[ T](\d\d:\d\d:\d\d)\.(\d{7})Z?$")
JLECMD_PIN = {"pinned": True, "unpinned": False}
JLECMD_ROWS_SHOWN = 20
JLE = {"runs": 0, "left_behind": 0}      # JLECmd runs made, and how many processes settle() ended after them (the CSV a program writes is read: it is held to the process rules; lnkinfo's pipe is not)


def jlecmd_why(why):
    return why if len(why) <= 300 else why[:300] + "..."


def jlecmd_table(csv_path):
    """(table, None) or (None, why): JLECmd's CSV for one jump list, as {entry number: its compared fields}, or why it was not read."""
    import csv
    try:
        size = csv_path.stat().st_size
        if size >= JLECMD_BYTES:
            return None, "JLECmd's CSV reached the %d-byte cap: nothing was read from it" % JLECMD_BYTES
        rows, numbers, twice = {}, 0, []
        with open(csv_path, "r", encoding="utf-8-sig", newline="") as fh:
            reader = csv.DictReader(fh)
            missing = [c for c in JLECMD_COLUMNS if c not in (reader.fieldnames or [])]
            if missing:
                return None, "JLECmd's CSV has no column %s: its output is not in the shape this tool reads" % ", ".join(missing)
            for record in reader:
                numbers += 1
                try:
                    number = int((record["EntryNumber"] or "").strip())
                except ValueError:
                    return None, "JLECmd's CSV row %d has an EntryNumber that is not a whole number" % numbers
                m = JLECMD_TIME.match((record["LastModified"] or "").strip())
                pin = JLECMD_PIN.get((record["PinStatus"] or "").strip().lower())
                if m is None:
                    return None, "JLECmd's CSV row %d gives LastModified in a form that is not a date to 100 nanoseconds" % numbers
                if pin is None:
                    return None, "JLECmd's CSV row %d gives PinStatus as something other than Pinned or Unpinned" % numbers
                if number in rows:
                    twice.append(number)
                    continue
                rows[number] = {"path": record["Path"], "last_access": "%sT%s.%sZ" % m.groups(), "pinned": pin, "app_id": (record["AppId"] or "").strip().lower()}
        return {"rows": rows, "count": numbers, "twice": twice}, None
    except (OSError, UnicodeDecodeError, csv.Error) as exc:
        return None, "JLECmd's CSV could not be read: %s" % describe(exc)


def jlecmd_run(source, directory, seconds):
    """(table, None) or (None, why): JLECmd reads the jump list `source` and writes a CSV into a directory of its own under `directory`, which is removed
    afterwards. It runs through dotnet (the installed JLECmd is a wrapper that does), in this tool's process group, under communicate_bounded with `seconds`.
    Nothing it prints is kept: its output goes to files in that directory, and the kernel stops any one file at JLECMD_BYTES."""
    program = shutil.which("JLECmd")
    if not program:
        return None, "JLECmd is not in this image (it runs through dotnet; requires/host.json pins it)"
    try:
        work = tempfile.mkdtemp(dir=directory, prefix=".jlecmd-")
    except OSError as exc:
        return None, "JLECmd's output directory could not be made: %s" % describe(exc)
    TEMP_DIRS.append(work)
    try:
        argv = [program, "-f", os.path.abspath(source), "--csv", work, "--dt", "yyyy-MM-dd HH:mm:ss.fffffff", "-q"]
        with open(os.path.join(work, "stdout.txt"), "wb") as out, open(os.path.join(work, "stderr.txt"), "wb") as err:
            saved = None
            try:
                try:
                    import resource
                    soft, hard = resource.getrlimit(resource.RLIMIT_FSIZE)
                    if soft == resource.RLIM_INFINITY or soft > JLECMD_BYTES:
                        saved = (soft, hard)
                        resource.setrlimit(resource.RLIMIT_FSIZE, (JLECMD_BYTES, hard))
                except (ImportError, ValueError, OSError):
                    saved = None
                before = process_verdict()["left_behind"]
                proc = spawn(argv, stdout=out, stderr=err)
            except OSError as exc:
                return None, "JLECmd could not be started: %s" % describe(exc)
            finally:
                if saved is not None:       # only the child was to have the limit
                    try:
                        resource.setrlimit(resource.RLIMIT_FSIZE, saved)
                    except (ValueError, OSError):
                        pass
            JLE["runs"] += 1
            ACTIVE.append(proc)
            try:
                _o, _e, timed_out = communicate_bounded(proc, max(1.0, seconds))
            finally:
                if proc in ACTIVE:
                    ACTIVE.remove(proc)
            left = process_verdict()["left_behind"] - before
        if left > 0:
            JLE["left_behind"] += left
            return None, "JLECmd left %d process(es) running after it ended; they were ended before its CSV was read, so the CSV may be short and was not compared" % left
        if timed_out:
            return None, "JLECmd did not answer in %d seconds (it and what it started were ended)" % max(1, int(seconds))
        names = sorted(os.listdir(work))
        for name in names:
            try:
                if os.lstat(os.path.join(work, name)).st_size >= JLECMD_BYTES:
                    return None, "JLECmd's output reached the %d-byte cap: it was ended and nothing was read" % JLECMD_BYTES
            except OSError:
                pass
        if proc.returncode != 0:
            return None, "JLECmd exited %d (it could not read the jump list)" % proc.returncode
        csvs = [n for n in names if n.endswith("_AutomaticDestinations.csv")]
        if len(csvs) != 1:
            return None, "JLECmd wrote %d automatic-destinations CSV file(s), not the one expected (it may not have been able to read the jump list)" % len(csvs)
        return jlecmd_table(Path(work) / csvs[0])
    finally:
        shutil.rmtree(work, ignore_errors=True)
        if work in TEMP_DIRS:
            TEMP_DIRS.remove(work)


def jlecmd_compare(entries, table, app_id):
    """Field by field, for one jump list: the entry count, then per entry the path, the access time and the pin state, then the application id.
    Returns (compared, file-level differences, {entry number: differences}, {entry number: fields not compared, with why})."""
    compared = ["entry_count", "path", "access_time", "pin_state"]
    file_diff, per, skipped = [], {}, {}
    if len(entries) != table["count"]:
        file_diff.append({"field": "entry_count", "destlist": len(entries), "jlecmd": table["count"]})
    if table["twice"]:
        file_diff.append({"field": "entry_numbers", "jlecmd_lists_twice": table["twice"][:JLECMD_ROWS_SHOWN]})
    mine = set()
    for e in entries:
        number = e["entry_number"]
        mine.add(number)
        theirs = table["rows"].get(number)
        if theirs is None:
            per.setdefault(number, []).append({"field": "entry", "destlist": "present", "jlecmd": "absent"})
            continue
        if e["path"] != theirs["path"]:
            per.setdefault(number, []).append({"field": "path", "destlist": e["path"], "jlecmd": theirs["path"]})
        mine_time = e["last_access"]
        if mine_time is None and e.get("last_access_filetime") == "0":
            mine_time = "1601-01-01T00:00:00.0000000Z"       # FILETIME 0 is that instant; the DestList's own field is then "not set", and JLECmd prints the instant
        if mine_time is None:
            # a FILETIME past year 9999: this tool has no date for it, so there is nothing to compare, and the entry says so
            skipped.setdefault(number, []).append({"field": "access_time", "why": "the DestList's FILETIME %s is not a date this tool can show" % e.get("last_access_filetime")})
        elif mine_time != theirs["last_access"]:
            per.setdefault(number, []).append({"field": "access_time", "destlist": mine_time, "jlecmd": theirs["last_access"]})
        if e["pinned"] != theirs["pinned"]:
            per.setdefault(number, []).append({"field": "pin_state", "destlist": "pinned" if e["pinned"] else "unpinned", "jlecmd": "pinned" if theirs["pinned"] else "unpinned"})
    extra = sorted(n for n in table["rows"] if n not in mine)
    if extra:
        file_diff.append({"field": "entries", "only_in_jlecmd": extra[:JLECMD_ROWS_SHOWN], "only_in_jlecmd_count": len(extra)})
    if app_id:
        compared.append("application_id")
        wrong = sorted({r["app_id"] for r in table["rows"].values() if r["app_id"] != app_id.lower()})
        if wrong:
            file_diff.append({"field": "application_id", "file_name": app_id.lower(), "jlecmd": wrong[:JLECMD_ROWS_SHOWN]})
    return compared, file_diff, per, skipped


def jlecmd_check(run, path, entries, readable, cut, app_id):
    """The second read of one jump list's DestList: {result: agree | disagree | not_run, why / compared / differences, per_entry}.
    The caller does not call it for a container with no DestList stream."""
    stats = run.jlecmd

    def not_run(why, key):
        stats["not_run"] += 1
        stats["why_not_run"][key] = stats["why_not_run"].get(key, 0) + 1
        return {"result": "not_run", "why": jlecmd_why(why)}

    if not readable:
        return not_run("the DestList was not parsed by this tool: there is nothing to compare", "no DestList read")
    if cut:
        return not_run("the DestList was read only to its first %d entries: JLECmd's count cannot be compared with a part" % len(entries), "DestList cut")
    if not entries:
        return not_run("this tool read no entry of the DestList: there is nothing to compare", "no entries read")
    if stats["checked"] + stats["failed"] >= JLECMD_MAX:
        return not_run("more than %d jump lists in this run: the second read is made for the first %d" % (JLECMD_MAX, JLECMD_MAX), "budget")
    seconds = min(float(JLECMD_SECONDS), CLOCK["deadline"] - time.monotonic() - JLECMD_MARGIN)
    if seconds < 3:
        return not_run("the tool's own clock left less than %d seconds for JLECmd" % (JLECMD_MARGIN + 3), "clock")
    table, why = jlecmd_run(path, run.dir, seconds)
    if table is None:
        if not why.startswith("JLECmd is not in this image"):
            stats["failed"] += 1
        return not_run(why, re.sub(r"row \d+", "a row", why.split(" (")[0].split(": ")[0])[:120])
    compared, file_diff, per, skipped = jlecmd_compare(entries, table, app_id)
    stats["checked"] += 1
    stats["entries_agreed"] += len(entries) - len(per)
    stats["entries_disagreed"] += len(per)
    if file_diff or per:
        stats["disagreed"] += 1
    else:
        stats["agreed"] += 1
    return {"result": "disagree" if (file_diff or per) else "agree", "compared": compared, "jlecmd_entries": table["count"], "destlist_entries": len(entries),
            **({"differences": file_diff} if file_diff else {}), "per_entry": per, "per_entry_not_compared": skipped}


def jlecmd_entry(check, number):
    """One DestList entry's `integrity.jlecmd`, from the file's check."""
    if check["result"] == "not_run":
        return {"result": "not_run", "why": check["why"]}
    diffs = check["per_entry"].get(number)
    skipped = check["per_entry_not_compared"].get(number)
    left_out = {s["field"] for s in skipped or []}
    return {"result": "disagree" if diffs else "agree", "compared": [c for c in check["compared"] if c not in left_out],
            **({"differences": diffs} if diffs else {}), **({"not_compared": skipped} if skipped else {})}


# ---- the rows ----------------------------------------------------------------------------------------------------------------------------

class Run:
    def __init__(self, directory, limit, write_strings, started):
        self.dir, self.limit, self.started = directory, limit, started
        self.rows = FilePage(directory, "rows.jsonl", [str(directory), "rows"], limit)
        self.strings = FilePage(directory, "strings.jsonl", [str(directory), "strings"], limit)
        self.counts = {"files": 0, "containers": 0, "streams": 0, "destlist_entries": 0, "links": 0}
        self.integrity = {"ok": 0, "incomplete": 0, "disagrees": 0, "unreadable": 0}
        self.container_problems = 0
        self.not_attempted = []
        self.lnkinfo = {"checked": 0, "agreed": 0, "disagreed": 0, "not_run": 0, "why_not_run": {}}
        # JLECmd is counted per jump list (one read of a DestList); `failed` is the runs that were made and gave nothing to compare.
        self.jlecmd = {"checked": 0, "agreed": 0, "disagreed": 0, "not_run": 0, "failed": 0, "entries_agreed": 0, "entries_disagreed": 0, "why_not_run": {}}
        self.unread = 0
        self.lnk = load_sibling("lnk_parse")
        self.jumplist = load_sibling("jumplist")
        values = None
        for n in range(1, 1000):
            name = "strings-values.jsonl" if n == 1 else "strings-values-%d.jsonl" % n
            try:
                values = self.lnk.SecretValues(write_strings, "lnk_jumplist", "write_strings", "lnk_jumplist-" + name)
                break
            except self.lnk.SecretValuesRefused as exc:
                if write_strings and "already exists" in str(exc):
                    continue
                raise ValueError(str(exc))
        self.values = values
        self.held = self.lnk.Held(values)
        self.string_sink = _StringSink(self.strings)
        self.stopped = False

    def add(self, row):
        self.rows.add(row)

    def finish(self):
        self.values.close()
        return self.rows.finish(), self.strings.finish()


class _StringSink:
    def __init__(self, page):
        self.page = page
        self.context = {}

    def add(self, row):
        self.page.add({**self.context, **row})


def link_row(run, data, base_off, where):
    """Decode one link structure with lnk_parse and put the result in a row; `where` holds the source, stream, container extents."""
    run.string_sink.context = {"source": where["source"], "stream": where.get("stream")}
    decoded = run.lnk.parse_lnk(data, base_off, run.held, run.string_sink)
    row = {"row": "link", **where, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}
    if not decoded.get("ok"):
        row["integrity"] = {"status": "unreadable", "problems": [decoded.get("error", "not a link structure")]}
        row["decoded"] = None
        return row, decoded
    row["header"] = {k: decoded.get(k) for k in ("flags_hex", "file_attr", "created", "created_filetime", "accessed", "accessed_filetime", "written", "written_filetime", "file_length", "show_cmd")}
    row["target"] = {"kind": decoded.get("linkinfo_target_kind"), "path": decoded.get("linkinfo_target"), "volume": decoded.get("volume"), "network": decoded.get("network")}
    row["strings"] = {k: decoded.get(k) for k in ("name", "relative_path", "working_dir", "icon_location", "arguments_present", "arguments_chars", "arguments_first_token", "arguments_first_token_withheld") if k in decoded}
    # Every tracker block is kept (lnk_parse holds the first 16 apart from its inline page of ExtraData blocks, and counts all of them), so a tracker block past
    # that page is not lost; the row stays bounded.
    row["tracker"] = [{"machine": b.get("machine"), "droid_hex": b.get("droid_hex"), "droid_birth_hex": b.get("droid_birth_hex")} for b in decoded.get("tracker", [])]
    row["tracker_count"] = decoded.get("tracker_count", len(row["tracker"]))
    integrity = {"structure_complete": decoded.get("structure_complete"), "problems": list(decoded.get("problems", []))}
    if row["tracker_count"] > len(row["tracker"]):
        # lnk_parse keeps the first 16 tracker blocks apart from its inline page; a link with more says so, and the row is not complete.
        integrity["problems"].append("the link holds %d tracker blocks and the row keeps the first %d (tracker_count says how many)" % (row["tracker_count"], len(row["tracker"])))
    integrity["status"] = "ok" if decoded.get("structure_complete") and not integrity["problems"] else "incomplete"
    row["integrity"] = integrity
    row["decoded"] = decoded
    return row, decoded


def cross_check(run, row, decoded, source_path, data):
    """Read the structure again with lnkinfo, within the run's budget, and compare."""
    info = row["integrity"]
    if run.lnkinfo["checked"] >= LNKINFO_MAX:
        run.lnkinfo["not_run"] += 1
        run.lnkinfo["why_not_run"]["budget"] = run.lnkinfo["why_not_run"].get("budget", 0) + 1
        info["lnkinfo"] = {"ran": False, "why": "more than %d links in this run: the independent read is made for the first %d" % (LNKINFO_MAX, LNKINFO_MAX)}
        return
    path, temp = source_path, None
    if path is None:
        fd, temp = tempfile.mkstemp(dir=run.dir, prefix=".xcheck-", suffix=".lnk")
        TEMPS.append(temp)
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
        path = temp
    try:
        fields, why = lnkinfo_run(path, min(20.0, max(2.0, CLOCK["deadline"] - time.monotonic() - 1)))
    finally:
        if temp:
            try:
                os.unlink(temp)
                TEMPS.remove(temp)
            except (OSError, ValueError):
                pass
    if fields is None:
        run.lnkinfo["not_run"] += 1
        key = why.split(" (")[0][:60]
        run.lnkinfo["why_not_run"][key] = run.lnkinfo["why_not_run"].get(key, 0) + 1
        info["lnkinfo"] = {"ran": False, "why": why}
        return
    checked, differ = compare_lnkinfo(decoded, fields)
    run.lnkinfo["checked"] += 1
    info["lnkinfo"] = {"ran": True, "compared": checked, "agrees": not differ, **({"differences": differ} if differ else {})}
    if differ:
        run.lnkinfo["disagreed"] += 1
        if info["status"] == "ok":
            info["status"] = "disagrees"
    else:
        run.lnkinfo["agreed"] += 1


def finish_link(run, row, decoded, source_path, data):
    if row["integrity"]["status"] != "unreadable":
        cross_check(run, row, decoded, source_path, data)
    run.integrity[row["integrity"]["status"]] += 1
    run.counts["links"] += 1
    run.add(row)


def read_lnk_file(run, path, size):
    if size > MAX_LNK_BYTES:
        run.unread += 1
        run.add({"row": "file", "path": path, "kind": "lnk", "bytes": size, "status": "failed", "problems": ["the file is %d bytes, over the %d this tool reads whole; it was not parsed" % (size, MAX_LNK_BYTES)]})
        return
    with open(path, "rb") as fh:
        data = fh.read(MAX_LNK_BYTES + 1)
    run.add({"row": "file", "path": path, "kind": "lnk", "bytes": size, "sha256": hashlib.sha256(data).hexdigest(), "status": "read"})
    row, decoded = link_row(run, data, 0, {"source": path, "container": "file", "stream": None, "file_offset": 0, "extents": [{"stream_offset": 0, "file_offset": 0, "bytes": len(data)}]})
    finish_link(run, row, decoded, path, data)


def read_custom(run, path, size):
    jl = run.jumplist
    run.add({"row": "file", "path": path, "kind": "customDestinations-ms", "bytes": size, "status": "read",
             "method": "carved: the file is split at every 20-byte link header; its own container structure is not parsed"})
    with open(path, "rb") as fh:
        starts = jl.lnk_starts(fh, size)
        if not starts:
            run.add({"row": "file", "path": path, "kind": "customDestinations-ms", "status": "partial", "problems": ["no link structure header was found in this file"]})
            run.container_problems += 1
            return
        for i, offset in enumerate(starts):
            if out_of_time():
                run.stopped = True
                return
            length = (starts[i + 1] if i + 1 < len(starts) else size) - offset
            fh.seek(offset)
            data = fh.read(min(length, MAX_LNK_BYTES))
            row, decoded = link_row(run, data, offset, {"source": path, "container": "customDestinations-ms", "stream": None, "carved": True, "index": i,
                                                          "file_offset": offset, "extents": [{"stream_offset": 0, "file_offset": offset, "bytes": length}]})
            if length > MAX_LNK_BYTES:
                row["integrity"].setdefault("problems", []).append("the carved span is %d bytes; the first %d were parsed" % (length, MAX_LNK_BYTES))
                row["integrity"]["status"] = "incomplete"
            finish_link(run, row, decoded, None, data)


def read_automatic(run, path, size):
    with open(path, "rb") as fh:
        try:
            cfb = Cfb(fh, size)
        except CfbError as exc:
            run.unread += 1
            run.add({"row": "file", "path": path, "kind": "compound file", "bytes": size, "status": "failed", "problems": [str(exc)]})
            return
        except CfbTime:
            run.unread += 1
            run.stopped = True
            run.add({"row": "file", "path": path, "kind": "compound file", "bytes": size, "status": "failed",
                     "problems": ["the time limit was reached while the container's FAT was read: nothing of this file was examined"]})
            return
        # First everything is found out, then the rows are written: the container row carries every problem found, the ones the streams and the DestList add too.
        streams = cfb.streams()
        shown = []
        try:
            for s in streams:
                if out_of_time():
                    raise CfbTime()
                extents, whole, mine = cfb.extents(s)
                shown.append((s, extents, whole, mine, cfb.read(extents, 20)))
        except CfbTime:
            run.stopped = True
            cfb.flag("time", "the time limit was reached after %d of the %d streams were examined: the streams after them have no row" % (len(shown), len(streams)))
        has_destlist = any(s["path"] == "DestList" for s, _e, _w, _m, _h in shown) or any(s["path"] == "DestList" for s in streams)
        destlist_row, dest_entries, destlist = None, [], None
        for s, extents, whole, _mine, _head in shown:
            if s["path"] == "DestList":
                destlist = (s, extents)
        if destlist is not None:
            s, extents = destlist
            if s["size"] > MAX_DESTLIST_BYTES:
                destlist_row = {"row": "destlist", "source": path, "problems": ["the DestList stream is %d bytes, over the %d this tool reads; it was not parsed" % (s["size"], MAX_DESTLIST_BYTES)]}
                run.unread += 1
            else:
                parsed = run.jumplist.parse_destlist(cfb.read(extents, MAX_DESTLIST_BYTES))
                dest_entries = parsed.pop("entries")
                destlist_row = {"row": "destlist", "source": path, "version": parsed.get("destlist_version"), "entries_claimed": parsed.get("entries_claimed"),
                                "entries_read": len(dest_entries), "pinned_claimed": parsed.get("pinned_claimed"), "problems": parsed.get("problems", []),
                                "not_decoded": parsed.get("not_decoded", [])}
                if parsed.get("entries_not_read_from") is not None:
                    destlist_row["entries_not_read_from"] = parsed["entries_not_read_from"]
        elif streams and not run.stopped:
            # A container with no stream at all is what Windows leaves for an empty jump list (1,536 bytes: header, FAT, directory); one that holds streams and no
            # DestList is not a jump list, or its DestList's directory entry is damaged.
            cfb.flag("no-destlist", "there is no stream named DestList, and the container holds %d other stream(s): this is a compound file but not a jump list container (or the directory entry of its DestList is damaged)" % len(streams))
        by_stream, entry_rows = {}, []
        app_id = os.path.basename(path).split(".")[0] if re.fullmatch(r"[0-9a-fA-F]{16}", os.path.basename(path).split(".")[0]) else None
        jl_check = None
        if destlist_row is not None and not run.stopped:
            jl_check = jlecmd_check(run, path, dest_entries, "entries_claimed" in destlist_row, destlist_row.get("entries_not_read_from") is not None, app_id)
            destlist_row["integrity"] = {"jlecmd": {k: v for k, v in jl_check.items() if k not in ("per_entry", "per_entry_not_compared")}}
        heads = {s["path"].lower(): (head, whole) for s, _e, whole, _m, head in shown}
        destlist_cut = destlist_row is not None and destlist_row.get("entries_not_read_from") is not None
        dest_starts = [x[0] for x in destlist[1]] if destlist is not None else []
        for number_read, e in enumerate(dest_entries):
            if number_read & 0x3FF == 0x3FF and out_of_time():
                run.stopped = True
                cfb.flag("time", "the time limit was reached after %d of the %d DestList entries were matched to the streams: the entries after them have no row" % (number_read, len(dest_entries)))
                break
            extents = destlist[1]
            pieces = map_range(extents, dest_starts, e["stream_offset"], 0x82 + 2 * e["path_chars"])
            present = e["stream"] in heads
            e_row = {"row": "destlist_entry", "source": path, **e, "container_offset": pieces[0][0] if pieces else None,
                     "container_contiguous": len(pieces) == 1, "stream_present": present}
            if jl_check is not None:
                e_row["integrity"] = {"jlecmd": jlecmd_entry(jl_check, e["entry_number"])}
            if e["stream"] in by_stream:
                cfb.flag("destlist-twice", "DestList entries %d and %d both name stream %r" % (by_stream[e["stream"]]["entry_number"], e["entry_number"], e["stream"]))
            by_stream[e["stream"]] = e_row
            if present:
                head = heads[e["stream"]][0]
                e_row["stream_is_link"] = head == LNK_MAGIC
                if head != LNK_MAGIC:
                    cfb.flag("destlist-nonlink", "DestList entry %d names stream %r, which is not a shell link (its first bytes are %s): its content is not decoded" % (e["entry_number"], e["stream"], head[:8].hex() or "none"))
            entry_rows.append(e_row)
        for number, e_row in by_stream.items():
            if not e_row["stream_present"]:
                cfb.flag("destlist-nostream", "DestList entry %d names stream %r, which the container does not hold" % (e_row["entry_number"], number))
        container_problems = cfb.problems
        run.add({"row": "file", "path": path, "kind": "automaticDestinations-ms" if has_destlist else "compound file without a DestList", "bytes": size, "status": "read",
                 "application_id": app_id})
        run.add({"row": "container", "source": path, "major_version": cfb.major, "sector_size": cfb.ss, "mini_sector_size": cfb.mini_ss, "mini_stream_cutoff": cfb.cutoff,
                 "sectors_in_file": cfb.sectors, "fat_sectors": cfb.n_fat, "directory_entries": len(cfb.directory), "streams": len(streams),
                 "problems": container_problems, "problem_count": cfb.found.total(), "consistent": not container_problems})
        run.counts["containers"] += 1
        if container_problems:
            run.container_problems += 1
        if destlist_row is not None:
            run.add(destlist_row)
            if destlist_row.get("problems"):
                run.container_problems += 1
        for e_row in entry_rows:
            run.counts["destlist_entries"] += 1
            run.add(e_row)
        for s, extents, whole, mine, head in shown:
            if out_of_time():
                run.stopped = True
                return
            run.counts["streams"] += 1
            is_dest = s["path"] == "DestList"
            entry = by_stream.get(s["path"].lower())
            srow = {"row": "stream", "source": path, "name": s["path"], "bytes": s["size"], "storage": "mini stream" if s["size"] < cfb.cutoff else "sectors",
                    "start_sector": s["start"], "file_offset": extents[0][1] if extents else None, "contiguous": len(extents) <= 1,
                    "extent_count": len(extents), "extents": [{"stream_offset": a, "file_offset": o, "bytes": n} for a, o, n in extents[:MAX_EXTENTS_SHOWN]],
                    "chain_whole": whole, "is_link": head == LNK_MAGIC, "in_destlist": (bool(entry) or (None if destlist_cut else False)) if not is_dest else None}
            if len(extents) > MAX_EXTENTS_SHOWN:
                srow["extents_not_shown"] = len(extents) - MAX_EXTENTS_SHOWN
                srow["extents_note"] = "the first %d of %d extents are listed; the rest follow the stream's sector chain from the start sector" % (MAX_EXTENTS_SHOWN, len(extents))
            if mine:
                srow["problems"] = mine
            if not is_dest and has_destlist and not entry:
                srow["orphan"] = ("a stream none of the %d DestList entries read has an entry for (the DestList was read only to its first %d entries)" % (len(dest_entries), len(dest_entries))
                                  if destlist_cut else "a stream the DestList has no entry for")
            run.add(srow)
            if is_dest or head != LNK_MAGIC:
                continue
            if s["size"] > MAX_STREAM_BYTES:
                run.unread += 1
                run.add({"row": "link", "source": path, "stream": s["path"], "integrity": {"status": "unreadable", "problems": ["the stream is %d bytes, over the %d this tool reads; it was not parsed" % (s["size"], MAX_STREAM_BYTES)]}})
                run.integrity["unreadable"] += 1
                continue
            data = cfb.read(extents, MAX_STREAM_BYTES)
            where = {"source": path, "container": "automaticDestinations-ms", "stream": s["path"], "file_offset": extents[0][1] if extents else None,
                     "contiguous": len(extents) <= 1, "extents": srow["extents"], "destlist_entry": entry["entry_number"] if entry else None}
            if entry:
                where["destlist_path"] = entry["path"]
                where["destlist_last_access"] = entry["last_access"]
            row, decoded = link_row(run, data, 0, where)
            if not whole:
                row["integrity"].setdefault("problems", []).append("the stream's sector chain is shorter than its size: only the sectors it has were read")
                if row["integrity"]["status"] == "ok":
                    row["integrity"]["status"] = "incomplete"
            finish_link(run, row, decoded, None, data)
        for number, e_row in by_stream.items():
            if not e_row["stream_present"]:
                run.add({"row": "destlist_entry_without_stream", "source": path, "entry_number": e_row["entry_number"], "stream": number, "path": e_row["path"],
                         "note": "the DestList names a stream that the container does not hold (deleted, or a damaged directory)"})


def classify(path, name, size):
    with open(path, "rb") as fh:
        head = fh.read(20)
    if head[:20] == LNK_MAGIC:
        return "lnk"
    if head[:8] == OLE_MAGIC:
        return "cfb"
    lowered = name.lower()
    if lowered.endswith("customdestinations-ms"):
        return "custom"
    return None


WALK = {"skipped": 0, "unopened": 0, "stopped": False, "entries": 0}
SKIPPED_KEPT = 5000      # the files the walk passed over are counted; the first this many are named


def skip(skipped, item):
    WALK["skipped"] += 1
    if item.get("unopened"):
        WALK["unopened"] += 1
    if len(skipped) < SKIPPED_KEPT:
        skipped.append(item)


def collect(path, max_files):
    targets, skipped, over = [], [], 0
    if os.path.isdir(path):
        for root, dirs, files in os.walk(path, followlinks=False):
            if out_of_time():
                WALK["stopped"] = True
                break
            dirs.sort()
            for name in sorted(files):
                WALK["entries"] += 1
                if not (WALK["entries"] & 255) and out_of_time():
                    WALK["stopped"] = True
                    break
                full = os.path.join(root, name)
                lowered = name.lower()
                if not (lowered.endswith(".lnk") or lowered.endswith("destinations-ms")):
                    skip(skipped, {"file": full, "reason": "not named like a link or a jump list: not read"})
                    continue
                try:
                    st = os.lstat(full)
                except OSError as exc:
                    skip(skipped, {"file": full, "reason": "could not be examined: " + describe(exc), "unopened": True})
                    continue
                if not stat.S_ISREG(st.st_mode):
                    skip(skipped, {"file": full, "reason": ("a symbolic link is not followed" if stat.S_ISLNK(st.st_mode) else "not a regular file") + ": it was not opened", "unopened": True})
                    continue
                if len(targets) >= max_files:
                    over += 1
                    continue
                targets.append((full, st.st_size))
            if WALK["stopped"]:
                break
    else:
        try:
            st = os.stat(path)
        except OSError as exc:
            fail("the path could not be examined", path=path, reason=describe(exc))
        if not stat.S_ISREG(st.st_mode):
            fail("the path is not a regular file or a directory (a pipe, a socket or a device is never opened)", path=path, not_attempted=1)
        targets.append((path, st.st_size))
    return targets, skipped, over


def last_word(signum):
    forget_temps()
    print(json.dumps({"error": "stopped by signal %d before the answer was complete" % signum, "status": "interrupted",
                      "status_basis": "the tool was stopped by signal %d; nothing it had made is a result (the temporary files were removed)" % signum, "signal": signum}), flush=True)


def check_args(args):
    if not isinstance(args, dict):
        fail("the arguments are one JSON object")
    path = args.get("path")
    if not isinstance(path, str) or not path:
        fail("path is required: a link, a jump list, or a directory of them")
    limit = args.get("limit", 100)
    if isinstance(limit, bool) or not isinstance(limit, int) or limit < 1:
        fail("limit must be a positive whole number", limit=limit)
    seconds = args.get("max_seconds", DEFAULT_SECONDS)
    if isinstance(seconds, bool) or not isinstance(seconds, (int, float)) or not 1 <= seconds <= MAX_SECONDS:
        fail("max_seconds must be a number from 1 to %d" % MAX_SECONDS, max_seconds=seconds)
    max_files = args.get("max_files", DEFAULT_FILES)
    if isinstance(max_files, bool) or not isinstance(max_files, int) or max_files < 1:
        fail("max_files must be a positive whole number", max_files=max_files)
    write_strings = args.get("write_strings", False)
    if not isinstance(write_strings, bool):
        fail("write_strings must be true or false")
    return path, limit, float(seconds), max_files, write_strings


def main():
    install_signal_handlers()
    STATE["last_word"] = last_word
    try:
        args = json.load(sys.stdin)
    except ValueError as exc:
        fail("arguments are not valid JSON", reason=str(exc))
    path, limit, seconds, max_files, write_strings = check_args(args)
    if write_strings:
        job, out = os.environ.get("JOB_ID") or "", os.environ.get("OUT") or ""
        if not (job and out) or os.environ.get("SECRET_OUTPUT") != "1":
            fail("write_strings is refused: the text of a link's strings is written only in a job the harness runs as secret output (job_run with secret_output: true). Nothing was written.")
    CLOCK["deadline"] = time.monotonic() + seconds
    started = time.monotonic()
    targets, skipped, over = collect(path, max_files)
    identity = hashlib.sha256(json.dumps([path, [t for t in targets[:2000]], len(targets)]).encode("utf-8")).hexdigest()[:12]
    directory = output_directory(identity)
    try:
        directory.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        fail("the output directory could not be made", reason=describe(exc))
    try:
        run = Run(directory, limit, write_strings, started)
    except ValueError as exc:
        fail(str(exc))
    kinds = {}
    for full, size in targets:
        if out_of_time():
            run.stopped = True
            break
        try:
            kind = classify(full, os.path.basename(full), size)
            if kind is None:
                run.not_attempted.append({"file": full, "reason": "neither a link header, a compound file signature nor a customDestinations-ms name: not read"})
                continue
            run.counts["files"] += 1
            label = {"lnk": "shell link", "cfb": "compound file", "custom": "customDestinations-ms"}[kind]
            kinds[label] = kinds.get(label, 0) + 1
            if kind == "lnk":
                read_lnk_file(run, full, size)
            elif kind == "custom":
                read_custom(run, full, size)
            else:
                read_automatic(run, full, size)
        except OSError as exc:
            run.unread += 1
            run.add({"row": "file", "path": full, "status": "failed", "problems": ["could not be read: " + describe(exc)]})
    rows_result, strings_result = run.finish()
    unread_names = skipped + run.not_attempted
    unread_count = WALK["skipped"] + len(run.not_attempted)
    reasons = []
    if WALK["stopped"]:
        reasons.append("the tool's own clock (%d seconds) ran out during the directory walk, after %d entries: the files not yet reached were not looked at" % (int(seconds), WALK["entries"]))
    if run.stopped:
        reasons.append("the tool's own time limit (%d seconds) was reached: the file being read, if it was not read to its end, and the files after it were not read whole" % int(seconds))
    if over:
        reasons.append("%d file(s) past max_files (%d) were not read" % (over, max_files))
    unopened = WALK["unopened"]
    if unopened:
        reasons.append("%d file(s) named like a link or a jump list were not opened (a symbolic link is not followed; a pipe, a socket or a device is never opened): skipped_first and the receipt name them" % unopened)
    if run.not_attempted:
        reasons.append("%d file(s) were not read because their first bytes are neither a link, a compound file nor a customDestinations-ms name (skipped_first names them)" % len(run.not_attempted))
    if run.unread:
        reasons.append("%d file(s) or stream(s) could not be read whole" % run.unread)
    if run.container_problems:
        reasons.append("%d container problem(s) are named in the rows" % run.container_problems)
    if run.integrity["incomplete"] or run.integrity["unreadable"]:
        reasons.append("%d link(s) are incomplete and %d unreadable" % (run.integrity["incomplete"], run.integrity["unreadable"]))
    if run.integrity["disagrees"]:
        reasons.append("lnkinfo disagrees with lnk_parse on %d link(s)" % run.integrity["disagrees"])
    if run.jlecmd["disagreed"]:
        reasons.append("JLECmd disagrees with the DestList read on %d jump list(s) (%d DestList entries differ; integrity.jlecmd in the rows says how)" % (run.jlecmd["disagreed"], run.jlecmd["entries_disagreed"]))
    # What JLECmd wrote (its CSV) is read and compared: a process it left behind was ended before the CSV was read, and the jump list was not compared; where one cannot be ruled out (not Linux,
    # or PR_SET_CHILD_SUBREAPER refused) the CSV cannot be shown to be final. lnkinfo prints on a pipe and is not held to it.
    verdict = process_verdict()
    if JLE["left_behind"]:
        reasons.append("JLECmd left process(es) running after it ended (%d in all) and they were ended before its CSV was read: the second read of the DestList was not made for the jump list(s) concerned "
                       "(integrity.jlecmd says which)" % JLE["left_behind"])
    if JLE["runs"]:
        for why in verdict["unproven"]:
            reasons.append(why + ": JLECmd's CSV cannot be shown to be final")
    # lnkinfo's pipe is the only pipe this tool reads through the block (JLECmd's output goes to files): a cut at the byte cap means the independent read of the link(s) concerned
    # was not used (integrity.lnkinfo.ran is false for them, with the reason). The rows themselves are lnk_parse's reading and are not touched; the answer is partial because the
    # claim "agrees with lnkinfo" cannot be made for them. The cut is counted once for the whole run (PIPE_CUT), so this reason is given for every cut, not for a row.
    if PIPE_CUT["cut"]:
        reasons.append("%d lnkinfo call(s) were cut at %d bytes because a process that held lnkinfo's pipe after it ended went on writing: lnkinfo's output for those link(s) was not compared "
                       "(integrity.lnkinfo says which); the rows are lnk_parse's own reading" % (PIPE_CUT["cut"], POST_EXIT_BYTES))
    if not run.counts["files"] and WALK["stopped"]:
        status, basis = "partial", "; ".join(reasons)
    elif not run.counts["files"] and not unread_count:
        status, basis = "failed", "no file was read"
    elif not run.counts["files"]:
        status, basis = "failed", "no link or jump list was found to read (%d file(s) skipped)" % unread_count
    else:
        status = "partial" if reasons else "complete"
        basis = "; ".join(reasons) if reasons else "every file was read to its end, every container is consistent, and every link's structure is complete" + (
            " and agrees with lnkinfo where lnkinfo was run" if run.lnkinfo["checked"] else "") + (
            " and with JLECmd where JLECmd was run" if run.jlecmd["checked"] else "")
        if not reasons and run.lnkinfo["not_run"]:
            basis += "; lnkinfo, the independent reader, was not run for %d link(s) (lnkinfo.why_not_run says why)" % run.lnkinfo["not_run"]
        if not reasons and run.jlecmd["not_run"]:
            basis += "; JLECmd, the second reader of a DestList, was not run for %d jump list(s)%s (jlecmd.why_not_run says why)" % (
                run.jlecmd["not_run"], " and gave no result for %d of them" % run.jlecmd["failed"] if run.jlecmd["failed"] else "")
    receipt = {"parser": PARSER, "status": status, "status_basis": basis, "path": path, "counts": run.counts, "kinds": kinds, "integrity": run.integrity,
               "container_problems": run.container_problems, "lnkinfo": run.lnkinfo, "jlecmd": run.jlecmd, "skipped": unread_count, "walk_entries": WALK["entries"],
               "program_group": verdict}
    fd, tmp = tempfile.mkstemp(dir=directory, prefix=".receipt-")
    TEMPS.append(tmp)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump({**receipt, "skipped_files": unread_names[:5000]}, fh, indent=1)
        fh.write("\n")
    placed = place_without_replacing(Path(tmp), directory / "receipt.json")
    TEMPS[:] = [t for t in TEMPS if t != tmp]
    answer = {**receipt, "skipped_first": unread_names[:20], "rows": run.rows.page, "rows_total": rows_result["matched"], "rows_file": rows_result.get("all_results"),
              "strings_file": strings_result.get("all_results"), "string_locators": strings_result["matched"], "receipt": shown_path(placed),
              "secret_values": run.values.summary("JSON Lines, mode 0600: finding_id, link_offset, field, [offset, piece, continued_in_next,] value"),
              "elapsed_seconds": round(time.monotonic() - started, 2),
              "note": "Offsets inside a link's record are from the start of that link structure; file_offset and extents say where it sits in the file. lnk_parse decodes the link, "
                      "jumplist's layouts decode the DestList, lnkinfo is the independent read of a link and JLECmd, where it is installed, of a DestList; nothing here executes or resolves a target."}
    print(json.dumps(answer, indent=1))
    if status == "failed":
        sys.exit(1)


if __name__ == "__main__":
    exit_code = 0
    try:
        try:
            main()
        except SystemExit:
            raise
        except ValueError as exc:
            fail(str(exc))
        except Exception as exc:                                  # whatever hostile input does, the answer is JSON
            hold_stop_signals(quietly=True)
            forget_temps()
            print(json.dumps({"ok": False, "error": "the run failed", "status": "failed", "status_basis": "the tool stopped with an unexpected error", "reason": "%s: %s" % (type(exc).__name__, exc)}))
            sys.exit(1)
    except SystemExit as stop:
        exit_code = _code(stop)
    _leave(exit_code)
