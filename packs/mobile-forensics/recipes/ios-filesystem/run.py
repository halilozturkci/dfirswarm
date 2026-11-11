#!/usr/bin/env python3
"""Catalogue the forensic structures in an iOS full file-system tar.

The recipe is deliberately structural. It reads every tar header and no member
body, so the catalogue says which parser targets exist without turning a path
into a finding or extracting protected content.

Names are kept as the tar reader returned them. A member name is never trimmed
here (a leading dot or slash is part of it; the reader itself drops the trailing
slash of a directory's name): `path` shows it with tabs, newlines, backslashes
and bytes that are not UTF-8 escaped, and `path_b64` is its exact bytes. `n` is the member's position in the archive, from 0, so two members of
one name are two rows, and a database that occurs twice keeps both sizes and
both positions (sqlite.tsv: sizes joined with `|`, `members` listing
role=position, `types` the kind of each: a link has the size 0 and is not an
empty database). The classification of a name reads a lower-cased copy; the copy
is never what is written.

A database family is a main database with its -wal, -shm and -journal companions.
The main database is found by its suffix (.db, .sqlite, .sqlite3, .sqlitedb,
.storedata) or by being the file a companion belongs to (`x/db` with `x/db-wal`).
A database with neither a suffix nor a companion is not found by its name.

The tar is followed header by header, apart from the library that lists it
(the data between members is not read). The archive is complete only when its
end-of-archive block was seen (`tar_end` in coverage.json: reached or missing), a
header the library would refuse (a checksum that does not match, a number that
does not parse) stops the listing and is said, the number of members listed is
compared with the number of headers counted, and an extended header (a GNU long
name, a pax header) that declares more than 16 MiB is not read, since the library
would hold it whole in memory. The end of an archive is two zero blocks: a zero
block with a header after it is read past, as GNU tar and bsdtar do, and said
(partial); data after the two blocks is not read and is said. A compressed tar
(gzip, bzip2 or xz, by its magic) is decoded in pieces, with an output budget
(`--max-decompressed-bytes`, default 32 GiB): a tar that expands past it stops the
listing, and the run says partial, names the budget and the number of members
listed. A run never writes over an earlier run's output: if the output directory
already holds one of its files, it refuses.

The database families are grouped in a scratch SQLite file under the output
(deleted when the run ends), so a very large archive does not hold them in
memory, and the artefact rows are written as they are met.
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


import argparse
import base64
import datetime
import io
import json
import os
import sqlite3
import struct
import sys
import tarfile
import time
import zlib


IOS_MARKERS = (
    "private/var/mobile/",
    "private/var/containers/",
    "system/library/coreservices/systemversion.plist",
)
DEFAULT_BUDGET = 32 << 30      # decoded bytes of a compressed tar; the same as the Android backup recipe's
DEFAULT_SECONDS = 900          # for the listing: recipe.json limits.seconds is 1800, and the families are grouped and written after it (time that grows with the members)
SQLITE_SUFFIXES = (".db", ".sqlite", ".sqlite3", ".sqlitedb", ".storedata")
ROLES = ("db", "wal", "shm", "journal")
OUTPUTS = ("artifacts.tsv", "sqlite.tsv", "index.tsv", "coverage.json")


def target_of(value):
    text = open(value, encoding="utf-8").read() if os.path.isfile(value) else value
    target = json.loads(text)
    paths = target.get("paths") or []
    if not paths or not isinstance(paths[0], str):
        raise ValueError("the target names no path")
    return target, paths[0]


# --- tar watch: begin ----------------------------------------------------------------------------
# Held byte for byte equal in the four recipes that read a tar (a test compares the copies). The watch
# follows a tar header by header, apart from the library that lists it, and says what that library does
# not: whether the end-of-archive blocks came, whether a header would be refused (a checksum that does not
# match, a number that does not parse), how many members there are, and whether an extended header declares
# more than the library should be allowed to hold in memory (it reads a GNU long name or a pax header whole).
# The end of an archive is TWO zero blocks. One zero block with a header after it is not an end: GNU tar and bsdtar
# warn ("lone zero block") and read on, and so does the listing (the library is opened with ignore_zeros); the watch
# counts such blocks, and the run is partial for them.
EXTENDED_HEADER_LIMIT = 16 << 20
ZERO_BLOCK = b"\0" * 512
NO_DATA_TYPES = set(b"123456")        # hard link, symbolic link, character and block device, directory, fifo: the size is not followed by data


def tar_number(field):
    """A tar numeric field as the tar library reads it: octal text, or base-256 when the top bit is set."""
    if field[0] in (0o200, 0o377):
        n = 0
        for i in range(len(field) - 1):
            n = (n << 8) + field[i + 1]
        return -(256 ** (len(field) - 1) - n) if field[0] == 0o377 else n
    return int(bytes(field).split(b"\0")[0].decode("ascii").strip() or "0", 8)


def tar_header(block):
    """The size field of a header the tar library would accept, or None if it would refuse it."""
    try:
        for start, end in ((100, 108), (108, 116), (116, 124), (136, 148), (329, 337), (337, 345)):
            tar_number(block[start:end])
        checksum = tar_number(block[148:156])
        size = tar_number(block[124:136])
    except ValueError:
        return None
    unsigned = 256 + sum(block[:148]) + sum(block[156:])
    signed = 256 + sum(struct.unpack_from("148b", block)) + sum(struct.unpack_from("356b", block, 156))
    return size if checksum in (unsigned, signed) else None


def pax_size(data):
    """The `size` record of a pax header ("<length> <key>=<value>\\n" records), or None; one that is not a number reads as 0, as the library reads it."""
    size, pos = None, 0
    while pos < len(data):
        space = data.find(b" ", pos)
        if space < 0:
            break
        try:
            length = int(data[pos:space])
        except ValueError:
            break
        if length <= 0 or pos + length > len(data):
            break
        key, _, value = data[space + 1:pos + length - 1].partition(b"=")
        if key == b"size":
            try:
                size = int(value)
            except ValueError:
                size = 0
        pos += length
    return size


class TarWatch:
    def __init__(self):
        self.block = bytearray()
        self.skip = 0
        self.collect = 0
        self.collect_padding = 0
        self.collecting = None
        self.acc = bytearray()
        self.position = 0
        self.ended = False
        self.end_at = None           # where the end-of-archive blocks start
        self.zero_at = None          # a zero block just met, the first of the two that end the archive unless a header follows
        self.lone_zeros = 0          # zero blocks that a header followed: not an end
        self.lone_first = None       # where the first of them is
        self.tail_at = None          # the first byte that is not zero after the end-of-archive blocks
        self.zeroed_data = 0         # GNU long-name, long-link and pax headers whose data starts with a zero byte: a name block that was wiped
        self.violation = None        # the size an extended header declares, over the limit
        self.violation_at = None     # where that header starts
        self.bad_at = None           # where a header starts that the tar library would refuse
        self.truncated = False       # a walk reached the end of the file inside a header or its data
        self.members = 0
        self.next_size = None        # a pax `size` for the next member
        self.global_size = None      # one from a global pax header
        self.in_ext = False          # inside the extension blocks of a GNU sparse header
        self.after_ext = 0

    def stopped(self):
        return self.ended or self.violation is not None or self.bad_at is not None

    def stop_at(self):
        """Where the library must see the end of the data: before a header it must not read, or at the end block."""
        for at in (self.violation_at, self.bad_at, self.end_at):
            if at is not None:
                return at
        return None

    def feed(self, data):
        """Follow bytes as they flow past."""
        i, n = 0, len(data)
        while i < n and not self.stopped():
            if self.collect:
                take = min(self.collect, n - i)
                self.acc += data[i:i + take]
                self.collect -= take
                i += take
                self.position += take
                if not self.collect:
                    self.finish_pax()
                continue
            if self.skip:
                step = min(self.skip, n - i)
                self.skip -= step
                i += step
                self.position += step
                continue
            take = min(512 - len(self.block), n - i)
            self.block += data[i:i + take]
            i += take
            self.position += take
            if len(self.block) == 512:
                self.header(bytes(self.block))
                self.block.clear()
        if self.stopped():
            if self.ended and self.tail_at is None and i < n:
                rest = data[i:]
                if rest.count(0) != len(rest):
                    self.tail_at = self.position + len(rest) - len(rest.lstrip(b"\0"))
            self.position += n - i

    def walk(self, fh, size, until=None):
        """Follow a file that can seek, header to header: the data between headers is jumped over, not read."""
        while not self.stopped() and not self.truncated and (until is None or self.position < until):
            if self.collect:
                data = fh.read(self.collect)
                if len(data) < self.collect:
                    self.truncated = True
                    return
                self.acc += data
                self.position += len(data)
                self.collect = 0
                self.finish_pax()
                continue
            if self.skip:
                if self.position + self.skip > size:
                    self.truncated = True
                    return
                fh.seek(self.position + self.skip)
                self.position += self.skip
                self.skip = 0
                continue
            fh.seek(self.position)
            block = fh.read(512)
            if len(block) < 512:
                self.truncated = True
                return
            self.position += 512
            self.header(block)

    def look_past_end(self, fh, size):
        """For a tar on disk whose end blocks came: where the first byte that is not zero lies after them (padding to a record is zeros)."""
        if not self.ended or self.tail_at is not None:
            return
        at = self.end_at + 1024
        while at < size:
            fh.seek(at)
            chunk = fh.read(min(1 << 20, size - at))
            if not chunk:
                return
            data = chunk.lstrip(b"\0")
            if data:
                self.tail_at = at + len(chunk) - len(data)
                return
            at += len(chunk)

    def finish_pax(self):
        if self.acc[:1] == b"\0":
            self.zeroed_data += 1        # a name or a pax record never starts with a zero byte
        if self.collecting in (ord("L"), ord("K")):
            self.acc.clear()             # only its first byte was read: the library reads the name itself
            self.skip = self.collect_padding
            return
        size = pax_size(bytes(self.acc))
        if self.collecting in (ord("x"), ord("X")):
            # The library starts from the global records and lets this header's override them.
            self.next_size = size if size is not None else self.global_size
        else:
            if size is not None:
                self.global_size = size
            self.next_size = self.global_size     # a global header applies to the member that follows it
        self.acc.clear()
        self.skip = self.collect_padding

    def header(self, block):
        start = self.position - 512
        if self.in_ext:
            if not block[504]:
                self.in_ext = False
                self.skip = self.after_ext
            return
        if block == ZERO_BLOCK:
            if self.zero_at is None:
                self.zero_at = start
            else:
                self.ended, self.end_at = True, self.zero_at
            return
        if self.zero_at is not None:
            self.lone_zeros += 1
            if self.lone_first is None:
                self.lone_first = self.zero_at
            self.zero_at = None
        size = tar_header(block)
        if size is None or size < 0:
            self.bad_at = start
            return
        flag = block[156]
        if flag in b"xgX":
            if size > EXTENDED_HEADER_LIMIT:
                self.violation, self.violation_at = size, start
                return
            self.collecting, self.collect, self.collect_padding = flag, size, -size % 512
            if not size:
                self.finish_pax()
            return
        if flag in b"LK":
            if size > EXTENDED_HEADER_LIMIT:
                self.violation, self.violation_at = size, start
                return
            padded = -(-size // 512) * 512
            if size:
                self.collecting, self.collect, self.collect_padding = flag, 1, padded - 1       # its first byte is looked at: a wiped name starts with zero
            else:
                self.skip = padded
            return
        self.members += 1
        if flag in NO_DATA_TYPES:
            self.next_size = None
            return
        if self.next_size is not None:
            # A pax `size` record is the size of the entry it precedes, over the header's own.
            size = self.next_size
        self.next_size = None
        padded = -(-size // 512) * 512
        if flag == ord("S") and block[482]:
            self.in_ext, self.after_ext = True, padded
        else:
            self.skip = padded


def tar_verdict(watch, listed, cut_short=False):
    """What the watch saw, set against the `listed` members the library returned: (tar_end, limits, errors).

    `cut_short`: the bytes were stopped by a budget, so neither the end blocks nor the count is judged.
    """
    limits, errors = [], []
    if watch.violation is not None:
        tar_end = "not_reached"
        limits.append("a tar extended header at offset %d declares %d bytes, over the limit of %d: it is not read, and the listing stopped after %d members"
                      % (watch.violation_at, watch.violation, EXTENDED_HEADER_LIMIT, listed))
    elif watch.bad_at is not None:
        tar_end = "not_reached"
        errors.append("the tar header at offset %d is not one the tar reader accepts (a checksum that does not match, or a number that does not parse): the listing stopped there, after %d members"
                      % (watch.bad_at, listed))
    elif watch.ended:
        tar_end = "reached"
    elif cut_short:
        tar_end = "not_reached"
    else:
        tar_end = "missing"
        if watch.zero_at is not None:
            errors.append("the tar ends after one zero block at offset %d, and an archive ends with two (%d bytes read): it is cut short or damaged, and the listing is what came before"
                          % (watch.zero_at, watch.position))
        else:
            errors.append("the tar ends without its end-of-archive blocks (%d bytes read): the archive is cut short or damaged, and the listing is what came before the cut" % watch.position)
    if watch.lone_zeros:
        errors.append("%d lone zero block(s) inside the tar, the first at offset %d: an archive ends with two zero blocks, and this one goes on after each. GNU tar and bsdtar "
                      "warn and read on, and so does this listing, but the archive was written or damaged in a way a clean one is not"
                      % (watch.lone_zeros, watch.lone_first))
    if watch.zeroed_data:
        errors.append("%d GNU long-name, long-link or pax header(s) whose data starts with a zero byte: the data block was wiped, and the member that follows carries a name "
                      "the archive does not hold" % watch.zeroed_data)
    if watch.tail_at is not None and not cut_short:
        errors.append("data follows the tar's end-of-archive blocks (the first byte that is not zero is at offset %d of the tar): tar stops at the blocks and so does this listing, "
                      "so an archive appended to this one, or anything else after them, is not listed" % watch.tail_at)
    if not cut_short and listed != watch.members:
        errors.append("the tar reader listed %d members and a header-by-header walk counted %d: the two disagree, so the listing may be missing members" % (listed, watch.members))
    return tar_end, limits, errors
# --- tar watch: end ------------------------------------------------------------------------------


# --- tar listing: begin --------------------------------------------------------------------------
CLOCK_BYTES = 16 << 20       # the clock is read at least once for every this many decoded bytes of a compressed tar, so that one huge member cannot outlast max-seconds by more than the time to decode this much
# Held byte for byte equal in the three recipes that open a tar by its path (a test compares the copies).
# A plain tar is read through Guarded and a gzip, bzip2 or xz one through Decoded; both keep the watch
# just ahead of the library and give it an end of data where the watch stops it. The library is opened with
# ignore_zeros, so that a zero block with a header after it is read past, as GNU tar does (the watch has already
# cut the data at the two zero blocks that end the archive, so nothing past the end is read). Decoded has an
# output budget: a compressed tar that expands past it stops the listing, and the run says partial.
def compression_of(head):
    if head[:2] == b"\x1f\x8b":
        return "gz"
    if head[:3] == b"BZh":
        return "bz2"
    if head[:6] == b"\xfd7zXZ\x00":
        return "xz"
    return None


class Guarded(io.RawIOBase):
    """A plain tar on disk as a file for the tar library. A walk of the same file runs just ahead of the library, and
    the library is given an end of file where the walk stops it: before an extended header too large to hold, before a
    header it would refuse, or at the end-of-archive block."""

    def __init__(self, handle, walker, size, watch):
        self.handle, self.walker, self.size, self.watch = handle, walker, size, watch
        self.pos = 0

    def readable(self):
        return True

    def seekable(self):
        return True

    def tell(self):
        return self.pos

    def seek(self, offset, whence=0):
        self.pos = max(0, (offset, self.pos + offset, self.size + offset)[whence])
        return self.pos

    def readinto(self, target):
        self.watch.walk(self.walker, self.size, self.pos + len(target))
        stop = self.watch.stop_at()
        limit = self.size if stop is None else min(stop, self.size)
        count = max(0, min(len(target), limit - self.pos))
        if not count:
            return 0
        self.handle.seek(self.pos)
        data = self.handle.read(count)
        target[:len(data)] = data
        self.pos += len(data)
        return len(data)

    def finish(self):
        """The rest of the headers, so that the watch has its whole answer."""
        self.watch.walk(self.walker, self.size)
        self.watch.look_past_end(self.walker, self.size)


class Decoded(io.RawIOBase):
    """A gzip, bzip2 or xz stream as a plain file for the tar library, read in pieces and followed by the watch; nothing
    is served from the point where the watch stops it."""

    PIECE = 1 << 20

    def __init__(self, source, kind, watch, budget=None, deadline=None):
        self.source, self.kind, self.watch = source, kind, watch
        self.deadline = deadline      # the time (time.monotonic) past which the stream serves no more, or None
        self.looked = 0               # decoded bytes since the clock was last read
        self.timed_out = False        # the stream was ended because the deadline had passed
        self.budget = budget          # at most this many decoded bytes, or None
        self.produced = 0
        self.exceeded = False         # the stream held more than the budget
        self.errors = (zlib.error, ValueError, OSError)
        if kind == "gz":
            self.decoder = zlib.decompressobj(31)
        elif kind == "bz2":
            import bz2
            self.decoder = bz2.BZ2Decompressor()
        else:
            import lzma
            self.decoder = lzma.LZMADecompressor()
            self.errors += (lzma.LZMAError,)
        self.pending = b""
        self.buffer = bytearray()
        self.served = 0
        self.finished = False
        self.trouble = None    # what is wrong with the stream: it ended before its end marker, or its checksum does not hold

    def readable(self):
        return True

    def piece(self):
        """The next decoded piece, or None at the end of the stream or of the budget."""
        if self.exceeded or self.timed_out:
            return None
        out = self._piece()
        if out and self.deadline is not None:
            self.looked += len(out)
            if self.looked >= CLOCK_BYTES:
                self.looked = 0
                if time.monotonic() > self.deadline:
                    self.timed_out = True      # this piece is served; the next call ends the stream, in the middle of a member if need be
        if out is None or self.budget is None:
            return out
        room = self.budget - self.produced
        if len(out) > room:
            self.exceeded = True
            out = out[:max(room, 0)]
        self.produced += len(out)
        return out

    def _piece(self):
        d = self.decoder
        if self.kind == "gz":
            if not self.pending:
                if d.eof:
                    return None
                self.pending = self.source.read(self.PIECE)
                if not self.pending:
                    self.trouble = "the gzip stream ends before its end marker"
                    return None
            out = d.decompress(self.pending, self.PIECE)
            self.pending = d.unconsumed_tail
            return out
        if d.eof:
            return None
        chunk = b""
        if d.needs_input:
            chunk = self.source.read(self.PIECE)
            if not chunk:
                self.trouble = "the %s stream ends before its end marker" % self.kind
                return None
        return d.decompress(chunk, self.PIECE)

    def fill(self):
        while not self.buffer and not self.finished:
            try:
                out = self.piece()
            except self.errors as exc:
                raise OSError("the %s stream is damaged: %s" % (self.kind, exc))
            if out is None:
                self.finished = True
                break
            self.watch.feed(out)
            self.buffer += out
            stop = self.watch.stop_at()
            if stop is not None and self.served + len(self.buffer) > stop:
                del self.buffer[max(0, stop - self.served):]
                self.finished = True

    def readinto(self, target):
        self.fill()
        count = min(len(target), len(self.buffer))
        target[:count] = self.buffer[:count]
        del self.buffer[:count]
        self.served += count
        return count

    def finish(self):
        """The rest of the stream, so that the watch has its whole answer and the stream's own end marker and checksum are
        verified. A tar that stopped at a header the library would not read is not followed further."""
        while self.watch.violation is None and self.watch.bad_at is None:
            try:
                out = self.piece()
            except self.errors as exc:
                self.trouble = "the %s stream is damaged: %s" % (self.kind, exc)
                return
            if out is None:
                return
            self.watch.feed(out)


class NoMembers:
    """The listing of a tar whose very first header the watch would not let the library read."""

    members = []

    def __iter__(self):
        return iter(())

    def close(self):
        pass


class TarList:
    """A tar on disk, listed by the tar library behind a watch: `archive` is the library's TarFile, `watch` the watch.

    The data between members is not read for a plain tar, and a compressed one is read once, decoded in pieces. The
    library is given an end of data before any extended header the watch will not let it hold, and before a header it
    would refuse; `finish()` lets the watch follow the rest, and `watch` then says whether the end block came.
    """

    def __init__(self, path, budget=None, deadline=None):
        self.watch = TarWatch()
        self.handle = open(path, "rb")
        self.walker = None
        head = self.handle.read(6)
        self.handle.seek(0)
        kind = compression_of(head)
        try:
            if kind is None:
                self.walker = open(path, "rb")
                self.source = Guarded(self.handle, self.walker, os.fstat(self.handle.fileno()).st_size, self.watch)
                mode = "r:"
            else:
                self.source = Decoded(self.handle, kind, self.watch, budget, deadline)
                mode = "r|"
                self.source = io.BufferedReader(self.source)
            self.archive = tarfile.open(fileobj=self.source, mode=mode, encoding="utf-8", errors="surrogateescape", ignore_zeros=True)
            if (self.watch.ended and self.watch.end_at == 0) or self.watch.zero_at == 0:
                raise tarfile.ReadError("empty file")        # only zero blocks: the library, which skips them, would list nothing and say nothing
        except tarfile.TarError:
            if self.watch.violation is not None:
                self.archive = NoMembers()
                return
            trouble = getattr(getattr(self.source, "raw", self.source), "trouble", None)
            self.close()
            if trouble:
                raise tarfile.ReadError(trouble)
            if self.watch.bad_at == 0:
                raise tarfile.ReadError("the first header is not a tar header (a checksum that does not match, or a number that does not parse)")
            raise

    def finish(self):
        source = self.source.raw if isinstance(self.source, io.BufferedReader) else self.source
        source.finish()

    def timed_out(self):
        """Whether the clock ended a compressed tar's stream, which can be inside a member."""
        source = self.source.raw if isinstance(self.source, io.BufferedReader) else self.source
        return bool(getattr(source, "timed_out", False))

    def exceeded(self):
        """Whether a compressed tar held more than the budget (the listing stopped there)."""
        source = self.source.raw if isinstance(self.source, io.BufferedReader) else self.source
        return bool(getattr(source, "exceeded", False))

    def trouble(self):
        """For a compressed tar, what is wrong with the stream itself (cut before its end marker, a checksum that does not hold); otherwise None."""
        source = self.source.raw if isinstance(self.source, io.BufferedReader) else self.source
        return getattr(source, "trouble", None)

    def close(self):
        archive = getattr(self, "archive", None)
        if archive is not None:
            archive.close()
        for handle in (self.handle, self.walker):
            if handle is not None:
                handle.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
        return False
# --- tar listing: end ----------------------------------------------------------------------------


def escaped(value):
    """One line, one field, nothing hidden; a byte that is not UTF-8 shows as \\xNN."""
    out = []
    for ch in value:
        o = ord(ch)
        if 0xDC80 <= o <= 0xDCFF:
            out.append("\\x%02x" % (o - 0xDC00))
        elif ch == "\\":
            out.append("\\\\")
        elif ch == "\t":
            out.append("\\t")
        elif ch == "\r":
            out.append("\\r")
        elif ch == "\n":
            out.append("\\n")
        elif o < 0x20 or o == 0x7F:
            out.append("\\x%02x" % o)
        else:
            out.append(ch)
    return "".join(out)


def b64(value):
    return base64.b64encode(value.encode("utf-8", "surrogateescape")).decode("ascii")


def utc(value):
    try:
        return datetime.datetime.fromtimestamp(value, datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except (OverflowError, OSError, ValueError):
        return ""


def member_type(member):
    if member.isfile():
        return "file"
    if member.isdir():
        return "dir"
    if member.issym():
        return "symlink"
    if member.islnk():
        return "hardlink"
    return "other"


def classify(path):
    low = "/" + path.lower().strip("/")
    base = low.rsplit("/", 1)[-1]
    if base in ("sms.db", "callhistory.storedata", "addressbook.sqlitedb"):
        return "communications"
    if base == "knowledgec.db" or "/coreduet/knowledge/" in low:
        return "knowledge"
    if "/biome/" in low or "/biomestreams/" in low or base.endswith(".segb"):
        return "biome-segb"
    if ("/uuidtext/" in low or "/timesync/" in low or "/logd/" in low
            or base.endswith(".tracev3") or ".logarchive/" in low):
        return "unified-log"
    if "/keychains/" in low or base in ("keychain-2.db", "keychain-backup.plist"):
        return "keychain"
    if base == "photos.sqlite" or "/photodata/" in low:
        return "photos"
    if (base == ".com.apple.mobile_container_manager.metadata.plist"
            or "/mobileinstallation/" in low or base == "applicationstate.db"):
        return "app-container-map"
    if base in ("systemversion.plist", "lastbuildinfo.plist"):
        return "device-info"
    return None


def sqlite_base(path):
    low = path.lower()
    for suffix in ("-wal", "-shm", "-journal"):
        if low.endswith(suffix):
            return path[:-len(suffix)], suffix[1:]
    if low.endswith(SQLITE_SUFFIXES):
        return path, "db"
    return None, None


def detect(path, budget=DEFAULT_BUDGET):
    if not os.path.isfile(path):
        return "unknown", "not a readable file, so it cannot be told what it holds"
    try:
        with TarList(path, budget) as listing:
            for member in listing.archive:
                low = member.name.lower()
                if any(marker in low for marker in IOS_MARKERS):
                    return True, "tar members have an iOS full file-system root"
                listing.archive.members = []
            if listing.watch.violation is not None:
                return "unknown", "tar has no iOS full file-system marker before a header the scan does not read (an extended header of %d bytes at offset %d)" % (listing.watch.violation, listing.watch.violation_at)
    except OSError as exc:
        return "unknown", "the file could not be read, so it cannot be told what it holds: %s" % exc
    except (tarfile.TarError, EOFError) as exc:
        return False, "not a readable tar: %s" % exc
    return False, "tar has no iOS full file-system marker"


def run(path, out, budget=DEFAULT_BUDGET, seconds=DEFAULT_SECONDS):
    if any(os.path.lexists(os.path.join(out, name)) for name in OUTPUTS):
        # Before anything is written: an earlier run's files stay as they are.
        print(json.dumps({"ok": False, "status": "failed", "status_basis": "the output directory already holds the files of an earlier run, and this recipe never writes over one: nothing was run", "why": "the output directory already holds a file of an earlier run (%s): the recipe does not write over it" % ", ".join(n for n in OUTPUTS if os.path.lexists(os.path.join(out, n)))}))
        return None
    os.makedirs(out, exist_ok=True)
    # Said before the listing starts: a run the harness stops at its limit leaves this, and is read as partial.
    with open(os.path.join(out, "coverage.json"), "w", encoding="utf-8") as handle:
        json.dump({"recipe": "ios-filesystem", "status": "partial", "covered": "started; the listing did not finish (stopped before its end)",
                   "status_basis": "the run started and the listing had not finished when this was written: a run that is stopped before its end leaves this account",
                   "limits_hit": [], "errors": ["the run ended before the listing did"]}, handle, indent=2, sort_keys=True)
        handle.write("\n")
    deadline = time.monotonic() + seconds
    timed_out = False
    artifacts_path = os.path.join(out, "artifacts.tsv")
    sqlite_path = os.path.join(out, "sqlite.tsv")
    scratch = os.path.join(out, "sqlite-families.work.db")
    if os.path.lexists(scratch):
        os.unlink(scratch)
    work = sqlite3.connect(scratch)
    # m: the members of a database family; a: every other member, to find a main database that has no suffix.
    work.execute("CREATE TABLE m (base BLOB NOT NULL, role TEXT NOT NULL, size INTEGER NOT NULL, n INTEGER NOT NULL, kind TEXT NOT NULL)")
    work.execute("CREATE TABLE a (name BLOB NOT NULL, size INTEGER NOT NULL, n INTEGER NOT NULL, kind TEXT NOT NULL)")
    members = 0
    families_rows = 0
    categories = {}
    artifact_rows = 0
    errors, limits = [], []
    tar_end = "missing"
    try:
        with open(artifacts_path, "w", encoding="utf-8", newline="\n") as artifacts:
            artifacts.write("category\tpath\tbytes\tmtime_utc\ttype\tn\tpath_b64\n")
            try:
                with TarList(path, budget, deadline) as listing:
                    try:
                        for member in listing.archive:
                            if not members % 256 and time.monotonic() > deadline:
                                timed_out = True
                                break
                            name = member.name
                            kind = member_type(member)
                            category = classify(name)
                            if category:
                                categories[category] = categories.get(category, 0) + 1
                                artifact_rows += 1
                                artifacts.write("%s\t%s\t%d\t%s\t%s\t%d\t%s\n" % (
                                    category, escaped(name), member.size, utc(member.mtime), kind, members, b64(name)))
                            base, role = sqlite_base(name)
                            raw = name.encode("utf-8", "surrogateescape")
                            if base is not None:
                                work.execute("INSERT INTO m VALUES (?,?,?,?,?)", (base.encode("utf-8", "surrogateescape"), role, member.size, members, kind))
                                families_rows += 1
                            else:
                                work.execute("INSERT INTO a VALUES (?,?,?,?)", (raw, member.size, members, kind))
                            members += 1
                            listing.archive.members = []
                    except (tarfile.TarError, EOFError, OSError) as exc:
                        if not listing.timed_out():      # the time limit says it, below
                            errors.append("tar traversal stopped: %s" % exc)
                    timed_out = timed_out or listing.timed_out()
                    try:
                        if not timed_out:
                            listing.finish()
                    except (tarfile.TarError, EOFError, OSError):
                        pass
                    if listing.trouble():
                        errors.append("the compressed tar is cut short or damaged: %s" % listing.trouble())
                    cut_short = listing.exceeded() or timed_out
                    tar_end, found_limits, found_errors = tar_verdict(listing.watch, members, cut_short)
                    limits += found_limits
                    errors += found_errors
                    if timed_out:
                        limits.append("time limit of %g seconds for the listing (the recipe's own is longer): the listing stopped after %d members" % (seconds, members))
                    if listing.exceeded():
                        limits.append("decompressed output budget of %d bytes (the listing stopped after %d members)" % (budget, members))
            except (tarfile.TarError, EOFError, OSError) as exc:
                errors.append("tar traversal stopped: %s" % exc)
        work.execute("CREATE INDEX a_name ON a (name)")
        work.execute("CREATE INDEX m_base ON m (base, n)")
        # A main database with no suffix is the member a companion belongs to: the one whose name is the companion's base.
        work.execute("INSERT INTO m SELECT a.name, 'db', a.size, a.n, a.kind FROM a WHERE a.name IN (SELECT base FROM m WHERE role != 'db')")
        work.commit()
        databases = 0
        with open(sqlite_path, "w", encoding="utf-8", newline="\n") as handle:
            handle.write("path\tdb_bytes\twal_bytes\tshm_bytes\tjournal_bytes\tpath_b64\tmembers\ttypes\n")
            bases = [row[0] for row in work.execute("SELECT DISTINCT base FROM m ORDER BY base")]
            for base in bases:
                sizes = {role: [] for role in ROLES}
                where, kinds = [], []
                for role, size, n, kind in work.execute("SELECT role, size, n, kind FROM m WHERE base = ? ORDER BY n", (base,)):
                    sizes[role].append(str(size))
                    where.append("%s=%d" % (role, n))
                    kinds.append("%s=%s" % (role, kind))
                name = base.decode("utf-8", "surrogateescape")
                handle.write("%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n" % (
                    escaped(name), "|".join(sizes["db"]), "|".join(sizes["wal"]), "|".join(sizes["shm"]),
                    "|".join(sizes["journal"]), base_to_b64(base), ",".join(where), ",".join(kinds)))
                databases += 1
    finally:
        work.close()
        try:
            os.unlink(scratch)
        except OSError:
            pass
    with open(os.path.join(out, "index.tsv"), "w", encoding="utf-8", newline="\n") as handle:
        handle.write("file\twhat\n")
        handle.write("artifacts.tsv\tiOS forensic structures by category, path, size, archive mtime, type and member position (path_b64 is the exact name)\n")
        handle.write("sqlite.tsv\tSQLite-family files grouped with WAL, SHM and rollback-journal companions: every occurrence's size, member position and type (| joins repeats); a database with no suffix and no companion is not found by its name\n")
    coverage = {
        "recipe": "ios-filesystem",
        "status": "partial" if errors or limits else "complete",
        "status_basis": ("partial because " + "; ".join([str(r).replace("\n", " ") for r in (limits + errors)[:3]]) + (" (and %d more in limits_hit and errors)" % (len(limits + errors) - 3) if len(limits + errors) > 3 else ""))
        if errors or limits else "the listing reached the end of the tar, no limit was hit and nothing was damaged",
        "covered": "%d tar members; %d forensic structures; %d SQLite families" % (members, artifact_rows, databases),
        "categories": dict(sorted(categories.items())),
        "not_covered": "artifact contents, deleted data, decryption, semantic findings, nested archives",
        "limits_hit": limits,
        "errors": errors,
        "tar_end": tar_end,
    }
    with open(os.path.join(out, "coverage.json"), "w", encoding="utf-8") as handle:
        json.dump(coverage, handle, indent=2, sort_keys=True)
        handle.write("\n")
    return coverage


def base_to_b64(base):
    return base64.b64encode(base).decode("ascii")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("detect", "run"))
    parser.add_argument("--target", required=True)
    parser.add_argument("--out")
    # The kickoff's census asks every detect step with --probe-out DIR, a
    # place for what the probe wants kept (evidence_catalog.py). Refused here,
    # it was a usage error (exit 2) for every input of a run, and a phone's
    # tar was catalogued as a member list only. Detect reads tar headers
    # and keeps nothing, so the directory is taken and left empty.
    parser.add_argument("--probe-out")
    parser.add_argument("--max-decompressed-bytes", type=int, default=DEFAULT_BUDGET)
    parser.add_argument("--max-seconds", type=float, default=DEFAULT_SECONDS)
    args = parser.parse_args()
    if args.max_decompressed_bytes < 1:
        print(json.dumps({"ok": False, "status": "failed", "status_basis": "an argument was refused, so nothing was run", "error": "--max-decompressed-bytes must be positive"}))
        return 2
    try:
        _, path = target_of(args.target)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(json.dumps({"ok": False, "status": "failed", "status_basis": "the target could not be read, so nothing was run", "error": str(exc)}))
        return 2
    if args.command == "detect":
        applies, why = detect(path, args.max_decompressed_bytes)
        print(json.dumps({"applies": applies, "why": why}))
        return 2 if applies == "unknown" else 0 if applies else 1
    if not args.out:
        print(json.dumps({"ok": False, "status": "failed", "status_basis": "run was given no output directory, so nothing was run", "error": "run needs --out DIR"}))
        return 2
    applies, why = detect(path, args.max_decompressed_bytes)
    if applies is not True:
        print(json.dumps({"ok": False, "status": "failed", "status_basis": "the target is not one this recipe reads, so nothing was run", "why": why}))
        return 2
    coverage = run(path, args.out, args.max_decompressed_bytes, args.max_seconds)
    if coverage is None:
        return 2
    print(json.dumps({"ok": True, "status": coverage["status"], "status_basis": coverage["status_basis"], "artifacts": sum(coverage["categories"].values())}))
    return 0


if __name__ == "__main__":
    exit_code = 0
    try:
        sys.exit(main())
    except SystemExit as stop:
        exit_code = _code(stop)
    _leave(exit_code)
