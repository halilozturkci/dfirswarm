#!/usr/bin/env python3
"""Reassemble PowerShell Script Block Logging records (event 4104) into script blocks, and say how whole each block is.

The records are event 4104 of `Microsoft-Windows-PowerShell/Operational` (Windows PowerShell) and of `PowerShellCore/Operational`
(PowerShell 7), which are kept apart: a block is the records that share a source, a Computer and a ScriptBlockId, put in order by
MessageNumber. Per block the answer gives the number of fragments the records say it has (MessageTotal) against the distinct numbers
seen, the numbers missing (as ranges), the numbers seen more than once (and whether the copies are equal), MessageTotal values that
disagree, numbers outside 1..MessageTotal, the Path field, the Level of the records (3 is a Warning: PowerShell logged that block
by itself because it looked suspicious) and the length of the text, and per fragment the EventRecordID and the record's byte offset.

The input is an `.evtx` file, read with the same chunk code evtx_query and evtx_carve carry (the file is read to its end; a chunk
the reader cannot read is a problem and the answer is partial), or a JSON Lines file of evtx_query rows (`input_format` "jsonl"), taken
by path: this tool imports no other tool. A row of evtx_query went through that tool's boundary, so a script text it withheld is a
placeholder there: such a fragment is counted under `fragments_text_withheld_upstream` and its block is not whole.

THE CONTENT IS NEVER EVALUATED, DECODED OR SHOWN. The answer and its files carry metadata: counts, lengths, numbers, ids and a status
per block. The reassembled text of the blocks is written only when `write_text` is true, to a file under $OUT with mode 0600 (one JSON
Lines line per block), and only in a job the harness runs as secret output; elsewhere `write_text` is refused as JSON before anything
is made. No hash or digest of a block or of a fragment is written anywhere: fragments are compared for equality in memory with a keyed
value that exists for one run and is never printed or stored.

A bound of the work is a state of the answer, never a clean one: the records examined, the fragments kept (at most 200,000, in at most
100,000 blocks) and the clock (the run has its own, below the manifest's) are counted, and what they cut makes the answer partial.
"""
import hashlib
import hmac
import json
import os
import re
import stat
import struct
import sys
import tempfile
import time
import xml.etree.ElementTree as ET
from pathlib import Path

# Lossless paging (the same in every library tool that pages): the page an
# agent reads stays small, and when there are more rows the whole result is
# written as JSON Lines under work/<agent>/tool-output and named.
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


# BEGIN SHARED EVTX READ
# The same text is in evtx_query and evtx_carve (a windows-forensics test holds the copies equal). python-evtx follows a chunk's string and
# template tables without a bound: a table entry whose next pointer names itself never ends, and nothing in the library has a clock. So a
# chunk is checked before the library is given it (chain_problem), whatever else it holds is read under a timer of its own (chunk_guard,
# which raises ChunkTimeout inside the library and gives the chunk up), and the whole run has a clock below the manifest's (out_of_time).
# SIGTERM, SIGINT and SIGHUP are cooperative: inside the library they unwind it (Interrupted), elsewhere they are noted and the next
# check_stop() raises, so that a result file is closed between two rows and never in the middle of one.
import signal
import struct
import time

CHUNK_MAGIC = b"ElfChnk\x00"
CHUNK_SIZE = 65536
HEADER_BYTES = 0x80
CHUNK_SECONDS = 8
CLOCK = {"deadline": None}
STOP = {"signal": None, "in_library": False}


class ChunkTimeout(BaseException):
    """A chunk took longer than CHUNK_SECONDS to read. BaseException: a library that catches Exception does not swallow it."""


class Interrupted(BaseException):
    def __init__(self, signum):
        super().__init__(signum)
        self.signum = signum


def set_deadline(seconds):
    CLOCK["deadline"] = time.monotonic() + seconds


def out_of_time():
    return CLOCK["deadline"] is not None and time.monotonic() > CLOCK["deadline"]


def _on_alarm(signum, _frame):
    raise ChunkTimeout()


def _on_signal(signum, _frame):
    if STOP["in_library"]:
        raise Interrupted(signum)
    STOP["signal"] = signum


def install_signal_handlers():
    signal.signal(signal.SIGALRM, _on_alarm)
    for signum in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(signum, _on_signal)


def check_stop():
    if STOP["signal"] is not None:
        raise Interrupted(STOP["signal"])


class chunk_guard:
    """`with chunk_guard():` the library is called under a CHUNK_SECONDS timer (and never longer than the run's clock has left); a stop
    signal unwinds it. Not for code that writes a result: that runs outside it."""

    def __enter__(self):
        left = CLOCK["deadline"] - time.monotonic() if CLOCK["deadline"] is not None else CHUNK_SECONDS
        check_stop()
        STOP["in_library"] = True
        signal.setitimer(signal.ITIMER_REAL, max(0.05, min(CHUNK_SECONDS, left)))
        return self

    def __exit__(self, *exc):
        signal.setitimer(signal.ITIMER_REAL, 0)
        STOP["in_library"] = False
        return False


def reject_signature(head):
    """Why the 128 bytes after an ElfChnk signature are not a chunk header, or None when they could be one. The layout is the format's (the
    libevtx notes on the EVTX chunk header): the first and last record numbers at 0x08 and 0x10, the header size (0x80) at 0x28, the offset
    of the last record at 0x2C and of the free space at 0x30, each inside the 64 KiB chunk. python-evtx's ChunkHeader reads whatever it is
    given without complaint, so this check is the tool's own."""
    if len(head) < HEADER_BYTES:
        return "the file ends %d bytes after the signature and a chunk header is %d bytes" % (len(head), HEADER_BYTES)
    first, last = struct.unpack_from("<QQ", head, 0x08)
    header_size, last_offset, next_offset = struct.unpack_from("<III", head, 0x28)
    if header_size != HEADER_BYTES:
        return "its header size is %d, not %d" % (header_size, HEADER_BYTES)
    if last_offset > CHUNK_SIZE or next_offset > CHUNK_SIZE:
        return ("its record offsets (last %d, free space %d) lie outside a %d-byte chunk"
                % (last_offset, next_offset, CHUNK_SIZE))
    if next_offset > 0x200 and first > last:
        return "its first record number %d is after its last, %d" % (first, last)
    return None


def chain_problem(raw):
    """Why `raw` (one chunk) must not be handed to python-evtx, or None. It mirrors ChunkHeader._load_strings and _load_templates, which
    follow 64 string chains and 32 template chains until a next pointer of 0: a pointer that names an offset already seen is a loop, one
    outside the chunk is a read past it."""
    if len(raw) < 0x200:
        return "the chunk is shorter than its 0x200-byte header area"
    for count, base, label in ((64, 0x80, "string"), (32, 0x180, "template")):
        for i in range(count):
            ofs = struct.unpack_from("<I", raw, base + 4 * i)[0]
            seen = set()
            while ofs > 0:
                if ofs in seen:
                    return "%s table entry %d loops back to offset 0x%x" % (label, i, ofs)
                seen.add(ofs)
                if label == "string":
                    if ofs + 8 > len(raw):
                        return "%s table entry %d points outside the chunk (0x%x)" % (label, i, ofs)
                    ofs = struct.unpack_from("<I", raw, ofs)[0]
                else:
                    if ofs < 10 or ofs + 4 > len(raw):
                        return "%s table entry %d points outside the chunk (0x%x)" % (label, i, ofs)
                    if raw[ofs - 10] != 0x0C or struct.unpack_from("<I", raw, ofs - 4)[0] != ofs:
                        break                       # python-evtx stops here itself (it logs "Unexpected token")
                    ofs = struct.unpack_from("<I", raw, ofs)[0]
                if len(seen) > 100000:
                    return "%s table entry %d chain longer than any chunk can hold" % (label, i)
    return None
# END SHARED EVTX READ


# BEGIN SHARED BOUNDARY
# BOUNDARY v2, the one text: the same text is in every tool that prints names, paths, event data, registry data, identifiers or table
# cells from evidence (tests/pack-boundary-shared.test.ts finds every copy under packs/ and tool-library/ and holds them equal: one variant, 16 carriers).
# It is the owner-approved HYBRID design: an allow-list for
# identifier-shaped fields, a deny-list for free text, and an independent backstop on the way out.
#
# Names defined here start with _b_ or _B_ where another shared block of a tool could define the same name (the WITHHOLDING block has _withheld and _USERINFO).
# THE CALLS A TOOL MAKES, and what the virtualization block called each (the three virtualization tools moved onto this text; the table is what they map to):
#   FIELDS, KEY_KINDS, bind_fields(table, key_kinds)           the table of field kinds, which the CALLER passes in (this text holds no tool's table);
#                                                              it was _FIELDS, _INHERIT and field_kind(); a digit run in a field name stands for any number
#                                                              (`ethernet#.address`), and a field the table does not list has the kind of the field above it
#   T(kind, text), show(s, kind, field)                        one string judged by its kind                         (the Shower, boundary_text, seal_text, seal_head)
#   sealed_text(text, kind, field), print_order(items, ...)    what an answer prints for a string; nothing counted    (seal_text without the count)
#   bind_values(enabled, tool), close_values(), values_summary()  the values file of a secret_output job            (bind_run(values, seconds))
#   seal_stop_after(seconds)                                   the clock: nothing is judged after it                  (bind_run's seconds, RUN["deadline"])
#   row_object(row)                                            one row of a paging file                               (row_text(row, where))
#   answer_object(doc), emit(doc)                              an answer, sealed and read back                        (answer_text(doc), backstop(value, where))
#   boundary_summary()                                         the "boundary" object; stopped_by is in it when judging stopped
#   OWN_NAMES                                                  the exact strings the run made and shows as they are   (OWN_NAMES)
# The kinds of a field: text (the default), name, path, key, url, host, hex, id (one of several forms of identifier: a GUID, a VMFS volume id, a device id, a VMware uuid, a MAC, a content id of 32 hexadecimal digits or a number; else a name), and the typed ones guid, digest, sid, mac, ip, time, number, version
# and, for virtualized storage and machines, vmfs (a VMFS volume id), device (naa., eui., wwn-0x, vml. and t10. ids), iqn, vmuuid (the VMware
# uuid of a machine), cid (a disk's content id), winhost (the name Windows gives a machine nobody named).
#
# LAYER 1, an allow-list per field type. A string the evidence supplied is shown as it is only when it fits the plain grammar of the
# type of the field it fills: a name (registry key and value names, event field names, provider and channel names, table and column
# names), a path (file names and paths, a registry path, a URL path), a key, a URL, or a typed id (GUID, SID, MAC, IP address, digest,
# time, number, version). The grammar is: letters of any script, digits, space and `_ - . $ @ ? : ~ + , # ( ) [ ] { } ' < > *`, at
# most 128 characters a component, no user-info shape (a `:` before an `@`), and no chain of 16 or more characters made of
# random-looking pieces (pieces that break into one- and two-character parts, flip between letters and digits, or are letters with
# no pronounceable word in them; a 16-hex id, a GUID or a number up to 18 digits is plain). Below 16 characters a chain is shown
# whatever it looks like: a short random password in a name is not recognised. A path is judged component by component and only the
# offending span is replaced; a string with a format, control or combining character is withheld whole.
#
# LAYER 2, for every kind, and it reads the string FIRST, as the evidence wrote it (the deny-list and the grammar cut spans out of a string
# and take with them the context these rules need: the user of `user:password@host`, the characters glued before `glpat-`): user-info up
# to the last `@` before the host (the password may hold a `/`, not a port); the value after a secret's name (password, secret, token,
# api/access/account/private key, credential, auth) found anywhere, up to a space or quote, and past a `& ; ,` that no `name=` follows;
# a PEM private key; a vendor token with its own prefix (AKIA, gh?_, github_pat_, xox?-, glpat-, sk_live_, SG., AIza, npm_, dop_v1_,
# ya29., sk-, JWT) in any case; a base64 key with its padding; and the same rules on a copy with invisible characters taken out and NFKC
# applied (a hit withholds the whole string). FREE TEXT (event data, messages, command lines, registry data strings, table cells) is on
# the deny-list: the same chain test applied to the text with its typed ids (GUID, SID, IP address, time, labelled digest, number) left
# alone, plus layer 2, and no character grammar.
#
# LAYER 3, the backstop, written apart from the layers above: every key and value of what is about to be written is read once more
# by its own normaliser and patterns (a PEM marker, a named secret, a run of 19 or more digits, a token prefix in any case, user-info, a
# run of 40 or more hex digits outside a typed field, a base64 run, a run that changes class as random text does; a typed field must hold
# the characters of its type; data written as hexadecimal is decoded and its printable text is read as text). It reads the shown string
# AND the original: a window of 12 characters of anything it calls secret in the original that is still in the shown string means the
# layers above left a piece of a secret between two cuts. A string it finds suspect is replaced by <withheld N bytes: backstop: why>,
# counted, its place named in boundary.replaced_at (built from the keys on the way as they are SHOWN, or their positions), and the
# answer is partial. A placeholder is only a placeholder when its reason is one of the fixed list. The names of the components of the Windows
# component store (WinSxS: lower case, a public key token, a language or `none`, a hash) are not judged by the backstop in a name or key slot:
# a real SOFTWARE hive lists them by the thousand and their hash looked random to it; layer 1 judges them as it does every name.
#
# ONE WAY OUT: emit() writes an answer, row_object() makes a row of a paging file, and both seal every key and value first (a value that is not
# a string, a number or a container is sealed as the text str() makes of it). Binary data written as hex (a REG_BINARY value, an ESE
# binary column) is decoded and its printable views (Latin-1, UTF-16LE and UTF-16BE, and runs holding full-width characters read as UTF-8 and UTF-16LE with
# the width folded) are judged by the free-text rules, by both layers and the
# backstop; hex that holds a secret-shaped text is withheld, and any other hex is shown (random bytes with no text in them are printed).
# What is withheld is a placeholder with its length and the reason; its original goes to the values file only when write_values was
# asked for in a job run as secret output. A list of names is printed in the order of the text shown for each, the placeholders of
# withheld names in a random order that is new every run (print_order); a `contains` filter is applied to the text the answer PRINTS (the
# string after the layers and the backstop, sealed_text), never to what is withheld or replaced, and contains_check says when the needle
# could have been in what is hidden. Every string is judged in linear time (a string is read to 256 KiB, the pieces the backstop compares
# are at most 64, a PEM body at most 20,000 characters), and an answer or a row that takes longer than SEAL_BUDGET seconds to seal, or that is
# still being sealed at the seal stop of the tool (seal_stop_after: a point in time after which nothing is judged, not a stop of the tool's own
# work, which has its own clock), has the rest of its strings replaced whole (<withheld N bytes: backstop: the judging time ran out>) and is
# partial; what stays readable past that point is the names the tool made itself (OWN_NAMES) and strings of 15 characters or fewer of letters,
# digits, `_` and `.` that do not start like a vendor token (and, in a field of a typed kind, fit the grammar of its type). The seal stop is 3.5 seconds before the
# tool's time limit: the string in progress finishes after it, and one string of 256 KiB takes up to 2.3 seconds to judge on a loaded machine (the worst measured).
# A run has a second bound: past MAX_JUDGED_CHARS characters judged (the final answer is always judged), a string not judged before is withheld by its size in the
# same way. boundary.stopped_by says which bound stopped the judging and boundary.strings_withheld_by_the_stop how many strings it withheld; the answer is partial.
# NOT RECOGNISED, by design: a secret that does not look like one (a plain password, a pronounceable passphrase, a UUID-shaped key,
# anything under 16 characters in a name, a secret hidden in words or in an encoding this block does not read).
import collections
import hashlib
import signal
import time
import unicodedata

LMIN = 16
MAX_ONE_STRING = 1 << 18
MAX_HEX_JUDGED = 1 << 20
MAX_PIECES = 64                 # the pieces of a string the backstop compares with what was shown (it stops collecting at this many)
MAX_PEM_BODY = 20000            # a PEM body is read to this many characters (a 16,384-bit RSA key is about 13,000)
SEAL_BUDGET = 10.0              # seconds one answer, or one row of a paging file, may take to be sealed; a tool may set another
_CLOCK = {"deadline": None, "stop": None}
_BIGRAMS_TEXT = "aaabacadaeafagahaiajakalamanaoapaqarasatauavawaxayazbabbbcbdbebfbhbibjblbmbnbobpbrbsbtbubvbycacbcccdcecfchcickclcncocqcrcsctcucydadbdcdddedfdgdhdidjdldmdndodpdrdsdtdudvdwdyeaebecedeeefegeheiejekelemeneoepeqereseteuevewexeyezfafbfcfdfefffiflfofrftfufygagbgdgegfggghgiglgmgngogrgsgtgugwgyhahbhchdhehfhhhihlhmhnhohphrhshthuhwhyiaibicidieifigihiiijikiliminioipiqirisitiuiviwixizjajejijojukakbkekfkhkikkklkmknkokpkrksktkukwkylalblcldlelflglhlilklllmlnlolplrlsltlulvlwlymambmemfmimlmmmnmompmrmsmumwmynanbncndnenfngnhninjnknlnmnnnonpnqnrnsntnunvnwnxnynzoaobocodoeofogohoiojokolomonooopoqorosotouovowoxoyozpapbpcpepfphpiplpmpnpoppprpsptpupwpyqurarbrcrdrerfrgrhrirjrkrlrmrnrorprqrrrsrtrurvrwryrzsasbscsdsesfsgshsiskslsmsnsospsqsrssstsusvswsytatbtctdtetftgthtitltmtntotptrtstttutvtwtytzuaubucudueufuguhuiukulumunuoupurusutuvuxuyuzvavevivovuvywawbwdwewfwhwiwkwlwmwnwowrwswtwuwyxaxcxexhxixoxpxtxuxxxyyaybycydyeyfygyhyiylymynyoypyrysytyuywyxyyyzzazezizlzozuzyzz"           # the 474 letter pairs that words and identifiers use (the system word list and Python identifiers)
_BIGRAMS = frozenset(_BIGRAMS_TEXT[i:i + 2] for i in range(0, len(_BIGRAMS_TEXT), 2))
BOUNDARY = {"withheld": 0, "by": collections.Counter(), "replaced": 0, "replaced_by": collections.Counter(), "where": [], "not_listed": 0}
OWN_NAMES = set()               # exact strings this run made and shows as they are (file names of its own results)
FIELDS = {}                     # a JSON key -> the kind of what it holds (a tool fills this in, or passes it to bind_fields); a key it does not list has the kind of the key above it (text at the top)
KEY_KINDS = {}                  # a JSON key holding a dict -> the kind of that dict's own keys (registry value names are paths); default: name
MAX_WHERE = 200
MAX_JUDGED_CHARS = 400000000    # characters one run may have judged (every string of its answers and paging files); past it a string not judged before is withheld by its size
FINAL_GRACE_CHARS = 4000000     # the final answer may always be judged: the cap is raised by this much, and is not spent again by the strings already withheld
_STOP = {"cap": MAX_JUDGED_CHARS, "chars": 0, "by": None, "strings": 0}   # why judging stopped (None: it did not), and how many strings it withheld by their size


class T(str):
    """A string with its field type, made by the tool where it knows the type (a registry type, an event field, a column)."""
    kind = "text"

    def __new__(cls, kind, text):
        self = super().__new__(cls, text)
        self.kind = kind
        return self


def _mark(n, label, unit="characters"):
    return "<withheld %d %s: %s>" % (n, unit, label)


# the reasons a placeholder can give: a fixed list, so that text which only looks like a placeholder is not taken for one (and not skipped by the rules)
_CHECKS = ("a PEM marker", "a named secret", "a token prefix", "user-info", "not the typed grammar", "a long digit run", "a long hexadecimal run",
           "a base64 run with / and +", "a padded base64 run", "a random-looking run", "a part of a secret-shaped text", "the judging time ran out")
_LABELS = ("not a plain name", "token-shaped text", "user-info", "secret value", "private key", "long number", "rest of a long string",
           "binary data over the judged size", "binary data holding a secret-shaped text", "invisible characters in a name", "not a port", "query value", "fragment",
           "not a guid", "not a digest", "not a sid", "not a mac", "not a ip", "not a time", "not a number", "not a version",
           "not a vmfs", "not a device", "not a iqn", "not a vmuuid", "not a cid", "not a winhost") + \
          tuple("backstop: " + c for c in _CHECKS) + tuple("backstop: in binary data: " + c for c in _CHECKS)
_MARK = re.compile(r"<withheld [0-9]{1,10} (?:characters|bytes)(?:: (?:%s))?>|\[withheld: [0-9]{1,10} (?:characters|bytes)\]"
                   % "|".join(re.escape(x) for x in sorted(_LABELS, key=len, reverse=True)))
_VALUES = {"fh": None, "shown": None, "written": 0, "seen": set(), "count": 0}   # "seen": 16-byte digests of the originals written (at most 200,000)


class ValuesRefused(Exception):
    pass


def bind_values(enabled, tool):
    """The values file: the originals of what the boundary withheld, in a job run as secret output and only when asked for. Decided before
    anything is opened or created (the harness sets SECRET_OUTPUT=1 for a secret job's process)."""
    if not enabled:
        return None
    job, out = os.environ.get("JOB_ID") or "", os.environ.get("OUT") or ""
    if not (job and out) or os.environ.get("SECRET_OUTPUT") != "1":
        raise ValuesRefused("write_values is refused: the originals of what was withheld are written only in a job the harness runs as secret output "
                            "(job_run with secret_output: true), where the file is a sealed secret output. Nothing was written.")
    name = "%s-values.jsonl" % re.sub(r"[^A-Za-z0-9_.-]", "_", tool)
    path = Path(out) / name
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    except FileExistsError:
        raise ValuesRefused("the values file already exists: %s" % path)
    except OSError as exc:
        raise ValuesRefused("the values file could not be created: %s: %s" % (path, exc.strerror or exc))
    _VALUES["fh"] = os.fdopen(fd, "w", encoding="utf-8")
    _VALUES["shown"] = "store/jobs/%s/out/%s" % (re.sub(r"[^A-Za-z0-9_.-]", "_", job), name)
    return _VALUES["shown"]


def close_values():
    fh = _VALUES["fh"]
    if fh is not None:
        fh.flush()
        os.fsync(fh.fileno())
        fh.close()
        _VALUES["fh"] = None


def values_summary():
    return {"requested": _VALUES["shown"] is not None, "values_file": _VALUES["shown"], "written": _VALUES["written"], "contains_secret_values": _VALUES["written"] > 0,
            "format": "JSON Lines, mode 0600: id, field, label, length, value (the original text that was withheld)" if _VALUES["shown"] else None}


_EVENTS = [None]               # while a string is judged only to see what the answer would print (sealed_text): its withholdings, counted when the answer prints it
_QUIET = [False]


def _b_withheld(original, label, field=""):
    n = len(original)
    if _EVENTS[0] is not None:
        _EVENTS[0].append((original, label, field))
        return _mark(n, label)
    BOUNDARY["withheld"] += 1
    BOUNDARY["by"][label] += 1
    fh = _VALUES["fh"]
    digest = hashlib.blake2b(original.encode("utf-8", "surrogatepass"), digest_size=16).digest() if fh is not None else None
    if fh is not None and digest not in _VALUES["seen"]:
        if len(_VALUES["seen"]) < 200000:
            _VALUES["seen"].add(digest)
        _VALUES["count"] += 1
        text = json.dumps({"id": _VALUES["count"], "field": field, "label": label, "length": n, "value": original}, ensure_ascii=False)
        try:
            text.encode("utf-8")
        except UnicodeEncodeError:
            text = json.dumps({"id": _VALUES["count"], "field": field, "label": label, "length": n, "value": original}, ensure_ascii=True)
        fh.write(text + "\n")
        _VALUES["written"] += 1
    return _mark(n, label)


# ---- normalisation ----------------------------------------------------------------------------------------------------------------
_STRIP_CATS = frozenset(("Cf", "Cc", "Mn", "Me", "Cs", "Co", "Cn", "Zl", "Zp"))
_FILLERS = frozenset((0x115F, 0x1160, 0x3164, 0xFFA0, 0x2800))


class _Strip(dict):
    def __missing__(self, o):
        if len(self) > 20000:
            self.clear()
        keep = unicodedata.category(chr(o)) not in _STRIP_CATS and o not in _FILLERS
        self[o] = o if keep else None
        return self[o]


_STRIP = _Strip()
_ESCAPED = re.compile(r"(?<!\\)\\+(?:u([0-9A-Fa-f]{4})|U([0-9A-Fa-f]{8})|x([0-9A-Fa-f]{2})|u\{([0-9A-Fa-f]{1,6})\})")


def _unescape_invisible(m):
    try:
        c = chr(int(m.group(1) or m.group(2) or m.group(3) or m.group(4), 16))
    except (ValueError, OverflowError):
        return m.group(0)
    return "" if (unicodedata.category(c) in _STRIP_CATS or ord(c) in _FILLERS) else m.group(0)


def _flat(text):
    """The text with invisible characters (and the escapes of such characters) taken out, and past ASCII in NFKC form."""
    if "\\u" in text or "\\U" in text or "\\x" in text:          # (the escape pattern needs a backslash and one of these)
        text = _ESCAPED.sub(_unescape_invisible, text)
    if text.isascii():
        return text if text.isprintable() else text.translate(_STRIP)
    out = text.translate(_STRIP)
    return unicodedata.normalize("NFKC", out) if not out.isascii() else out


# ---- layer 1: the allow-list ------------------------------------------------------------------------------------------------------
_PIECE = re.compile(r"[A-Z]{2,}s(?![a-z])|[A-Z]+(?![a-z])|[A-Z]?[a-z]+|[0-9]+")        # (GPOs, an acronym in the plural, is one piece)
_GUID = re.compile(r"\{?[0-9A-Fa-f]{8}-(?:[0-9A-Fa-f]{4}-){3}[0-9A-Fa-f]{12}\}?|[0-9a-f]{8}-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{12}")
_SID = re.compile(r"S-1-[0-9]{1,2}(?:-[0-9]{1,10}){1,15}")
_IPV4 = re.compile(r"(?<![0-9A-Za-z.])[0-9]{1,3}(?:\.[0-9]{1,3}){3}(?![0-9A-Za-z])")
_HEX_NUMBER = re.compile(r"(?<![0-9A-Za-z])0[xX][0-9A-Fa-f]{1,16}(?![0-9A-Za-z])")
# the publisher ids that follow the name of an AppX package family (the hash of the publisher's name), and the assembly public key tokens of Microsoft
_KNOWN_ID_WORDS = ("0x", "8wekyb", "cw5n1h", "kzf8qx", "31bf38", "b77a5c", "b03f5f")
_KNOWN_ID = re.compile(r"(?<![0-9A-Za-z])(?:8wekyb3d8bbwe|cw5n1h2txyewy|kzf8qxf38zg5c|31bf3856ad364e35|b77a5c561934e089|b03f5f7f11d50a3a|0x[0-9A-Fa-f]{1,16})(?![0-9A-Za-z])")
_NAME_SEPS = " _-.$@?:~+,#()[]{}'`<>*"
_PATH_EXTRA = "&!';=^%\""
_PCT = re.compile(r"%[0-9A-Fa-f]{2}")
_PCT_UNRESERVED = re.compile(r"%((?:4[1-9A-Fa-f]|5[0-9Aa]|6[1-9A-Fa-f]|7[0-9Aa]|3[0-9]|2[DdEe]|5[Ff]|7[Ee]))")
_JOIN_NAME, _JOIN_PATH = "-_+", "-_+/\\"
_CTRL = "\x01\x02\x03\x04\x05\x06\x07\x08\x09"


def _has(words, text):
    """Whether one of `words` is in `text` (a loop: a generator inside any() costs twice as much for the thousands of strings of a hive)."""
    for w in words:
        if w in text:
            return True
    return False


def _pronounceable(piece):
    p = piece.lower()
    bad = sum(1 for a, b in zip(p, p[1:]) if (a + b) not in _BIGRAMS)
    return bad <= 1 + len(p) // 10


_HEX_LOW_OR_UP = re.compile(r"[0-9a-f]+|[0-9A-F]+")
_HEX_ANY = re.compile(r"[0-9A-Fa-f]+")
_SEGMENT_MEMO = {}


def _structure_ok(seg):
    if seg.isdigit() and seg.isascii():
        return len(seg) <= 18
    if len(seg) <= 24 and _HEX_LOW_OR_UP.fullmatch(seg):
        return True                       # a hexadecimal id up to 24 digits (a USB serial, a 16-digit object id, a hash of a few bytes) is plain
    if len(seg) >= 20 and _HEX_ANY.fullmatch(seg):
        return False
    pieces = _PIECE.findall(seg)
    short = sum(1 for p in pieces if len(p) <= 2)
    if short > max(2, 0.4 * len(pieces)):
        return False
    flips = sum(1 for a, b in zip(seg, seg[1:]) if a.isdigit() != b.isdigit())
    if flips > 3 + len(seg) // 16:
        return False
    alpha = [p for p in pieces if p.isalpha()]
    if sum(len(p) for p in alpha) >= 12 and sum(len(p) for p in alpha) < 3.4 * len(alpha):
        return False
    return True


def _plain_segment(seg, lmin=None):
    lmin = LMIN if lmin is None else lmin
    if len(seg) < lmin:
        return True
    memo = (seg, lmin) if len(seg) <= 64 else None          # the same words come again and again in the records of one log
    if memo is not None:
        hit = _SEGMENT_MEMO.get(memo)
        if hit is not None:
            return hit
    if not _structure_ok(seg):
        ok = False
    else:
        ok = all(not (p.isalpha() and len(p) >= 6) or _pronounceable(p) for p in _PIECE.findall(seg))
    if memo is not None:
        if len(_SEGMENT_MEMO) >= 100000:
            _SEGMENT_MEMO.clear()
        _SEGMENT_MEMO[memo] = ok
    return ok


_EMBEDDED_ID = re.compile(r"(?<![A-Za-z0-9])(?:naa\.(?:[0-9a-fA-F]{32}|[0-9a-fA-F]{16})|eui\.[0-9a-fA-F]{16}|wwn-0x[0-9a-fA-F]{16}|vml\.[0-9a-fA-F]{20,40}|vsan:[0-9a-f]{16}-[0-9a-f]{16})(?![A-Za-z0-9])")
_EMBEDDED_T10 = re.compile(r"(?<![A-Za-z0-9])t10\.[A-Za-z0-9_.+-]{8,120}")
_EMBEDDED_WORDS = ("naa.", "eui.", "wwn-0x", "vml.", "vsan:", "t10.")


def _t10_plain(text):
    """Whether a t10. id reads as the id of a drive: every piece between underscores is 19 characters or fewer, and the serial (the last) is not a run of 17 or more hexadecimal digits."""
    pieces = text.split("_")
    return all(len(piece) <= 19 for piece in pieces) and not (len(pieces[-1]) >= 17 and _HEX_ANY.fullmatch(pieces[-1]) is not None)


_ONE_CASE_TAIL = re.compile(r"[A-Za-z]{20,64}")


def _letter_serial_spans(t):
    """The t10. and iqn. ids in `t` whose serial (the last piece of a t10. id) or target (after the last colon of an iqn. name) is 20 or more letters of one case that do not read as a word."""
    if "t10." not in t and "iqn." not in t:
        return []
    spans = []
    for m in _EMBEDDED_T10.finditer(t):
        last = m.group().split("_")[-1]
        if _ONE_CASE_TAIL.fullmatch(last) and (last.islower() or last.isupper()) and not _word_letters(last):
            spans.append((m.start(), m.end()))
    for m in _IQN_NAME.finditer(t):
        last = m.group().rsplit(":", 1)[-1]
        if _ONE_CASE_TAIL.fullmatch(last) and (last.islower() or last.isupper()) and not _word_letters(last):
            spans.append((m.start(), m.end()))
    return spans


_IQN_NAME = re.compile(r"(?<![A-Za-z0-9])iqn[.][0-9]{4}-[0-9]{2}[.][a-z0-9.-]{1,60}(?::[A-Za-z0-9._-]{1,64})?")


def _t10_hex_spans(t):
    """The t10. ids in `t` whose serial is a run of 17 or more hexadecimal digits: a drive's serial is not one (a random one is), and a run of hexadecimal digits is otherwise plain."""
    if "t10." not in t and "iqn." not in t:
        return []
    spans = []
    for m in _EMBEDDED_T10.finditer(t):
        last = m.group().split("_")[-1]
        if len(last) >= 17 and _HEX_ANY.fullmatch(last) is not None:
            spans.append((m.start(), m.end()))
    return spans + _letter_serial_spans(t)


def _mask_embedded(t):
    """`t` with the well-formed ids of devices in it (naa., eui., wwn-0x, vml., vsan: and a t10. id of a drive) replaced by `~`, so that the judging of a name or a path does not take their digits for a random run."""
    if not _has(_EMBEDDED_WORDS, t):
        return t
    t = _EMBEDDED_ID.sub(lambda m: "~" * len(m.group()), t)
    return _EMBEDDED_T10.sub(lambda m: "~" * len(m.group()) if _t10_plain(m.group()) else m.group(), t)


def _prepare(s, typed=True):
    """A same-length copy of `s` in which a GUID, a SID, an IPv4 address and a %XX escape are replaced by `~` and a non-ASCII letter by `e`;
    None when `s` holds a format, control or combining character, a non-NFKC character or a stray space character."""
    if not s.isascii():
        for ch in s:
            cat = unicodedata.category(ch)
            if cat[0] in "CM" or (cat[0] == "Z" and ch != " "):
                return None
        if unicodedata.normalize("NFKC", s) != s:
            return None
        s = "".join(ch if ch.isascii() else "e" for ch in s)
    t = _GUID.sub(lambda m: "~" * len(m.group()), s) if s.count("-") >= 3 else s    # (each pattern is tried only when the text holds what it cannot match without: a GUID has three hyphens or more)
    if typed:
        if "S-1-" in t:
            t = _SID.sub(lambda m: "~" * len(m.group()), t)
        if "." in t:
            t = _IPV4.sub(lambda m: "~" * len(m.group()), t)
        if _has(_KNOWN_ID_WORDS, t):
            t = _KNOWN_ID.sub(lambda m: "~" * len(m.group()), t)
        t = _mask_embedded(t)
    return _PCT.sub("   ", t) if "%" in t else t


def _unpercent(s):
    if "%" not in s:
        return None
    out = _PCT_UNRESERVED.sub(lambda m: chr(int(m.group(1), 16)), s)
    return out if out != s else None


_CHAINS = {}
_SEGMENT = re.compile(r"[A-Za-z0-9]+")


_SEGMENT_PLAIN = {}


def _is_plain_segment(seg):
    """_plain_segment(seg, 0), remembered for the plain ones only (a dict that is asked a hundred thousand times for the same words)."""
    if not _plain_segment(seg, 0):
        return False
    if len(seg) <= 64:
        if len(_SEGMENT_PLAIN) >= 100000:
            _SEGMENT_PLAIN.clear()
        _SEGMENT_PLAIN[seg] = True
    return True


def _bad_runs(t, join):
    """Intervals of `t` that are not plain, judged on CHAINS: maximal sequences of alphanumeric segments joined only by `join` characters. A
    chain is bad when (A) its random-looking segments, adjacent ones taken together, add up to LMIN characters or more, or (B) it is LMIN
    characters or longer, holds 8 or more characters of letter-and-digit-mixed segments, and holds no word of five or more letters."""
    pattern = _CHAINS.get(join)
    if pattern is None:
        pattern = _CHAINS[join] = re.compile(r"[A-Za-z0-9]+(?:[%s]+[A-Za-z0-9]+)*" % "".join(re.escape(c) for c in join))
    plain = _SEGMENT_PLAIN
    if all(plain.get(seg) or _is_plain_segment(seg) for seg in _SEGMENT.findall(t)):
        return []                                       # no chain holds a random-looking segment, so none is bad (the same answer as the loop below, without building the chains)
    bad = []
    for found in pattern.finditer(t):
        if found.end() - found.start() < LMIN:
            continue                                    # a chain shorter than LMIN is neither a run of LMIN random characters nor a long mixed chain
        chain = [(m.start(), m.end()) for m in _SEGMENT.finditer(t, found.start(), found.end())]
        total = sum(b - a for a, b in chain)
        if total < LMIN:
            continue
        rnd = [not _plain_segment(t[a:b], 0) for a, b in chain]
        if not any(rnd):
            continue
        run = None
        for (a, b), r in zip(chain, rnd):
            if r:
                run = [a, b, b - a] if run is None else [run[0], b, run[2] + (b - a)]
            else:
                if run is not None and run[2] >= LMIN:
                    bad.append((run[0], run[1]))
                run = None
        if run is not None and run[2] >= LMIN:
            bad.append((run[0], run[1]))
        mixed = sum(b - a for a, b in chain if not _structure_ok(t[a:b]))
        if total >= LMIN and mixed >= 8 and not any(len(p) >= 5 and p.isalpha() and _pronounceable(p) for a, b in chain for p in _PIECE.findall(t[a:b])):
            bad.append((chain[0][0], chain[-1][1]))
    return bad


_CHARS = {}


def _chars_ok(comp, extra_ok):
    if comp.isascii():
        pattern = _CHARS.get(extra_ok)
        if pattern is None:
            pattern = _CHARS[extra_ok] = re.compile("[A-Za-z0-9%s]*" % re.escape(_NAME_SEPS + extra_ok))
        return pattern.fullmatch(comp) is not None
    return all(ch.isalnum() or ch in _NAME_SEPS or ch in extra_ok for ch in comp)


def _userinfo_shape(t):
    return ":" in t and "@" in t and t.index(":") < t.rindex("@")


def _plain_name(s, extra_ok=""):
    if not s or len(s) > 128:
        return False
    t = _prepare(s)
    if t is None or not _chars_ok(t, extra_ok) or _userinfo_shape(t) or _secret_in_ident(t) or _t10_hex_spans(t):
        return False
    u = _unpercent(s)
    if u is not None:
        pu = _prepare(u)
        if pu is None or _bad_runs(pu, _JOIN_NAME):
            return False
    return not _bad_runs(t, _JOIN_NAME)


def _merge(spans):
    merged = []
    for a, b in sorted(spans):
        if merged and a <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], b))
        else:
            merged.append((a, b))
    return merged


_SPLIT = re.compile(r"([\\/])")
_DRIVE = re.compile(r"[A-Za-z]:|\?|\.")


def _path_spans(s, extra_ok=_PATH_EXTRA):
    t = _prepare(s)
    if t is None:
        return [(0, len(s))]
    bad, pos = [], 0
    if len(t) <= 255 and "@" not in t and t.isascii() and _chars_ok(t, extra_ok + "\\/") and not _secret_in_ident(t):
        parts = ()                       # (every character is allowed, no part is long and none can hold a user-info shape: no part is bad)
    else:
        parts = _SPLIT.split(t)
    for part in parts:
        a, b = pos, pos + len(part)
        pos = b
        judged = part.lstrip(_CTRL)
        if part in ("\\", "/") or part == "" or _DRIVE.fullmatch(part):
            continue
        if len(part) - len(judged) > 1 or len(part) > 255 or not _chars_ok(judged, extra_ok) or _userinfo_shape(judged) or _secret_in_ident(judged):
            bad.append((a, b))
    bad += _bad_runs(t, _JOIN_PATH) + _t10_hex_spans(t)
    u = _unpercent(s)
    if u is not None:
        pu = _prepare(u)
        if pu is None or _bad_runs(pu, _JOIN_PATH):
            bad.append((0, len(s)))
    return _merge(bad)


def _replace_spans(s, spans, label, field):
    out, last = [], 0
    for a, b in spans:
        out.append(s[last:a])
        out.append(_b_withheld(s[a:b], label, field))
        last = b
    out.append(s[last:])
    return "".join(out)


def _show_name(s, field):
    return s if _plain_name(s) else _b_withheld(s, "not a plain name", field)


def _show_path(s, field, extra_ok=_PATH_EXTRA):
    return _replace_spans(s, _path_spans(s, extra_ok), "not a plain name", field)


def _show_key(s, field):
    return _show_path(s, field, _PATH_EXTRA + "*^<>")


_URL = re.compile(r"^((?:[A-Za-z][A-Za-z0-9+.-]*:)?//)(?:([^/?#]*)@)?([^/?#]*)([^?#]*)(?:\?([^#]*))?(?:#(.*))?$", re.S)


def _show_host(s, field):
    """A host name is on the deny-list: a random-looking label of a host is evidence (a C2 name), not a secret. Layer 2 reads it first: the deny-list
    would replace a random user of `user:password@host` and leave the context layer 2 needs."""
    return _deny_text(_layer2(s, field), field)


def _show_value(v):
    return v if re.fullmatch(r"[0-9]{1,12}|true|false|null|yes|no", v) or (v.isalpha() and len(v) <= 24 and _plain_name(v)) else None


def _show_url(s, field):
    m = _URL.match(s)
    if not m:
        return _show_path(s, field)
    scheme, userinfo, host, path, query, frag = m.groups()
    out = scheme
    if userinfo is not None:
        out += (userinfo if _MARK.fullmatch(userinfo) else _b_withheld(userinfo, "user-info", field)) + "@"
    hostname, colon, port = host.partition(":") if not host.startswith("[") else (host, "", "")
    out += _show_host(hostname, field) + (colon + (port if port.isdigit() else _b_withheld(port, "not a port", field)) if colon else "")
    out += _show_path(path, field)
    if query is not None:
        pairs = []
        for pair in query.split("&"):
            k, eq, v = pair.partition("=")
            kk = _show_name(k, field) if k else k
            if eq:
                sv = _show_value(v)
                pairs.append(kk + "=" + (sv if sv is not None else _b_withheld(v, "query value", field)))
            else:
                pairs.append(kk)
        out += "?" + "&".join(pairs)
    if frag is not None:
        sv = _show_value(frag)
        out += "#" + (sv if sv is not None else _b_withheld(frag, "fragment", field))
    return out


_TYPED = {
    "guid": re.compile(_GUID.pattern),
    "digest": re.compile(r"(?:sha256:|sha1:|md5:)?[0-9A-Fa-f]{32,128}|T1[0-9A-Fa-f]{60,72}|[0-9]{1,6}:[A-Za-z0-9+/]{3,}:[A-Za-z0-9+/]{3,}"),
    "sid": re.compile(_SID.pattern),
    "mac": re.compile(r"(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}"),
    "ip": re.compile(r"[0-9]{1,3}(?:\.[0-9]{1,3}){3}|[0-9A-Fa-f:.]{2,45}(?:%[0-9A-Za-z_.-]{1,16})?"),
    "time": re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}(?:[T ][0-9:.]+(?:Z|[+-][0-9:]+)?)?|D:[0-9]{8,14}(?:[Zz+-][0-9']*)?|[0-9]{1,18}"),
    "number": re.compile(r"-?[0-9]{1,18}(?:\.[0-9]{1,18})?|0x[0-9A-Fa-f]{1,16}|(?:true|false|null)"),
    "version": re.compile(r"v?[0-9]+(?:\.[0-9A-Za-z]+){1,4}(?:[-+][0-9A-Za-z.]+)?"),
    # the identifiers of virtualized storage and machines: a VMFS volume id (8-8-4-12 hexadecimal digits), a SCSI device id (naa. with 16 or 32 digits, eui. and
    # wwn-0x with 16, vml. with 20 to 40, t10. with a vendor, a model and a serial), an iSCSI name, the VMware uuid of a machine (16 bytes, a `-` after the
    # eighth), the content id of a disk (8 digits) and the name Windows gives a machine nobody named (WIN- and 11 capitals and digits)
    "vmfs": re.compile(r"[0-9a-f]{8}-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{12}"),
    "device": re.compile(r"naa\.(?:[0-9a-fA-F]{16}|[0-9a-fA-F]{32})|eui\.[0-9a-fA-F]{16}|wwn-0x[0-9a-fA-F]{16}|vml\.[0-9a-fA-F]{20,40}|t10\.[A-Za-z0-9_.+-]{8,120}"),
    "iqn": re.compile(r"iqn\.[0-9]{4}-[0-9]{2}\.[a-z0-9][a-z0-9.-]{0,60}(?::[A-Za-z0-9._-]{1,40})?"),
    "vmuuid": re.compile(r"[0-9a-f]{2}(?: [0-9a-f]{2}){7}-[0-9a-f]{2}(?: [0-9a-f]{2}){7}"),
    "cid": re.compile(r"[0-9a-f]{8}"),
    "winhost": re.compile(r"WIN-[A-Z0-9]{11}"),
}
_ID_FORMS = ("guid", "vmfs", "vmuuid", "device", "mac", "cid", "number")      # the forms a field of kind `id` may hold (the kind of a field that holds one of several forms of identifier), else it is judged as a name
_CONTENT_ID = re.compile(r"[0-9A-Fa-f]{32}")
_NAMING_IDS = frozenset(("device", "iqn"))          # the ids that hold a name a person chose (a t10. vendor, model and serial; an iSCSI name): what they hold must read as a name, not as random text
_KNOWN_KINDS = frozenset(("text", "name", "path", "key", "url", "host", "hex", "label", "id")) | frozenset(_TYPED)
_NUMBER_RUN = re.compile(r"[0-9]+")


def bind_fields(table, key_kinds=None):
    """The field kinds of a tool, passed in by the tool (this text holds none): `table` maps a JSON key to the kind of what it holds, or to a function of
    the key of one item for a dict whose items have kinds of their own; `key_kinds` maps a key holding a dict to the kind of that dict's own keys. A kind
    this text does not know is refused (a misspelt kind would judge the field as free text without a word)."""
    for name, kind in list(table.items()) + list((key_kinds or {}).items()):
        if not isinstance(name, str) or not (callable(kind) or kind in _KNOWN_KINDS):
            raise ValueError("a field kind this text does not know: %r" % (name,))
    FIELDS.update(table)
    KEY_KINDS.update(key_kinds or {})


def _field_entry(name):
    """What FIELDS says of the field `name`; a digit run in a name stands for any number (`ethernet0.address` is `ethernet#.address`)."""
    entry = FIELDS.get(name)
    if entry is None and name and any(c.isdigit() for c in name):
        entry = FIELDS.get(_NUMBER_RUN.sub("#", name))
    return entry


# ---- layer 2: position and prefix rules -------------------------------------------------------------------------------------------
# user-info whose password holds a `/` (RFC 3986 says to encode it; people do not): after `//`, a user, a `:`, then everything up to the last `@` that is
# followed by a host; not `host:8080/...@...` (a port), whose first word after the colon is a number
_URL_USERINFO_SLASH = re.compile(r"(?<=//)(?![^\s/@:<>\"'`]*:[0-9]{1,5}(?:[/?#@]|$))[^\s/@:<>\"'`]{1,64}:[^\s<>\"'`]{1,128}(?=@[^\s/@<>\"'`]*(?:[\s/<>\"'`?#]|$))")
# a user the deny-list already replaced: `<withheld ...>:password@host`
_MARK_USERINFO = re.compile(r"(?P<mark><withheld \d+ (?:characters|bytes)[^<>]{0,70}>|\[withheld: \d+ characters\]):(?P<pw>[^\s/<>\"'`]{1,128})(?=@[^\s/@<>\"'`]*(?:[\s/<>\"'`?#]|$))")
_B_USERINFO = re.compile(r"(?<![A-Za-z0-9._%+-])(?!mailto:)[^\s/@:<>\"'`]{1,64}:[^\s/<>\"'`]{1,128}(?=@[^\s/@<>\"'`]*(?:[\s/<>\"'`?#]|$))")
_URL_USERINFO = re.compile(r"(?<=//)[^/?#\s@]+(?=@)")
_NAMED_HEAD = r"(?i:(?<![Bb]y)(?<![Cc]om)(?<![Oo]ver)(?<![Uu]nder)(?<![Tt]res)(?<![Ee]ncom)(?<![Ss]ur)(?<![Ii]m)pass(?:word|wd|phrase)?|pwd|secret|token|api[_-]?key|access[_-]?key|account[_-]?key|private[_-]?key|client[_-]?secret|credential|auth(?:orization)?|(?<![A-Za-z])(?:pw|sig|sas|otp|psk))" r"s?[0-9]{0,2}[\"']?[ \t]{0,3}[=:][ \t]{0,3}[\"']?"
_NAMED = re.compile(_NAMED_HEAD + r"(?!line[ \t]+[0-9])" + r"(?P<value>(?:(?i:token|bearer|basic|negotiate)[ \t]+(?=[A-Za-z0-9+/._~=-]{8}))?(?:[^\s\"'<>;,&]|[;,&](?![A-Za-z0-9_. -]{1,40}=)){1,512})")
# a placeholder (<redacted>, <password>, <***>) is not a value, but what is glued behind it is
_PLACEHOLDER = r"<(?i:redacted|hidden|masked|removed|omitted|secret|password|passwd|passphrase|pwd|pass|token|key|value|placeholder|empty|none|null|unset|your[ _-]?(?:password|secret|token|key)|\*{1,16})?>"
_PH_END = r"(?=[\s\"';,&\\<>)\]}]|\.(?:\s|$)|$)"
# a value in angle brackets after a secret's name (password=<hJaXeuQz>): withheld unless it reads as a placeholder word
_ANGLE_SPLIT = re.compile(r"[-_.+/=~]")
_NAMED_ANGLE = re.compile(_NAMED_HEAD + r"(?!" + _PLACEHOLDER + r")(?P<value><(?P<inner>[A-Za-z0-9+/_.~=-]{6,128})>)")
_NAMED_PH = re.compile(_NAMED_HEAD + _PLACEHOLDER + r"(?P<value>[^\s\"'<>;,&\\]{1,512})")
# the name of a flag that takes a secret (`-password x`, `--token x`, `--api-key x`, `-auth x`): the words below, any word with `secret` in it or ending in `token`, `key` or
# (after a letter or a digit) Key, Token, Password, Pwd, Pass, Secret, also after up to four words joined by `-` or `_`; `--key-file x` and `--keyboard x` are not (the name ends where the value begins)
_FLAG_NAME = (r"(?:[A-Za-z0-9]{1,20}[-_]){0,4}(?:(?i:passw(?:or)?d|passwd|pass(?:[-_]?phrase)?|pwd|pw|otp|[A-Za-z0-9]{0,20}secret[A-Za-z0-9]{0,20}|[A-Za-z0-9]{0,20}token|api[-_]?key|access[-_]?key|key|keypass|storepass|userpass|auth|authorization|bearer|psk|credentials?|community)"
              r"|[A-Za-z0-9]{1,20}(?-i:Key|Token|Password|Passwd|Pwd|Pass|Passphrase|Secret))")
# a placeholder, a space and a value built like a secret: the placeholder is not the value, the word after it is
_PH_SPACE = re.compile(r"(?:" + _NAMED_HEAD + r"|(?<![\w-])--?" + _FLAG_NAME + r"[ \t]+|(?<![\w-])(?i:set|enable)[ \t]+(?i:passw(?:or)?d|secret|passphrase|token)[ \t]+)"
                       + _PLACEHOLDER + r"[ \t]+(?P<value>[A-Za-z0-9]{8,40})(?![A-Za-z0-9])")
_NAMED_FLAG = re.compile(r"(?<![\w-])--?" + _FLAG_NAME + r"(?:=|[ \t]+)(?!-)(?!" + _PLACEHOLDER + _PH_END + r")(?![\x5ca-zA-Z0-9_./~:-]{1,120}[.](?i:key|pem|pub|crt|p12|pfx|jks)(?![A-Za-z0-9]))(?!(?:~|[.]{1,2})/[A-Za-z0-9_./-]{1,120}|/[A-Za-z0-9_.-]{1,40}(?:/[A-Za-z0-9_.-]{1,40})+)(?P<value>[^\s\"']+)")
_NAMED_SET = re.compile(r"(?<![\w-])(?i:set|enable)[ \t]+(?i:passw(?:or)?d|secret|passphrase|token)[ \t]+(?:[0-9][ \t]+)?(?!" + _PLACEHOLDER + _PH_END + r")(?P<value>[^\s\"']+)")
# in a name or a path component: a secret's name and, glued or after a separator or a space, something that is not a word (password-Zq7kP2mR, Token Zq7kP2mR, pwdZq7kP2mR), or a flag with its value
# (-password x, d--pwd x): a name that holds one is a command line, not a name
_IDENT_FLAG = re.compile(r"(?<![A-Za-z0-9])--?" + _FLAG_NAME + r"[ \t]+(?!-)\S")
_SECRET_THEN = re.compile(r"(?:(?i:passw(?:or)?d|passphrase|pwd|secret|token|credential|api[_-]?key|private[_-]?key|access[_-]?key|account[_-]?key)|(?<=-)(?i:pass|auth|bearer|psk))"
                          r"(?=s?[ \t_.-]*['\"(\[]?([A-Za-z0-9]{1,40}))")
_SECRET_THEN_TEXT = re.compile(r"(?<![A-Za-z0-9])(?i:passw(?:or)?d|passphrase|pwd|secret|token|credential|api[_-]?key|private[_-]?key|access[_-]?key|account[_-]?key)s?[ \t_.-]{1,3}['\"(\[]?(?P<value>[A-Za-z0-9]{7,40})(?![A-Za-z0-9])")
_GLUED_FLAG = re.compile(r"(?<![A-Za-z0-9])--?(?:[A-Za-z0-9]{1,20}[-_]){0,4}(?i:key|token|pass|password|pwd|secret)(?P<value>[A-Za-z0-9]{8,40})(?![A-Za-z0-9])")
_FLAG_THEN = re.compile(r"(?<![A-Za-z0-9])--?" + _FLAG_NAME + r"(?=[ \t_.-]*['\"(\[]?([A-Za-z0-9]{1,40}))")
_ID_SECRET_WORDS = ("pass", "pwd", "secret", "token", "key", "cred", "auth", "bearer", "psk", "otp", "pw", "community")
_WORD_PARTS = re.compile(r"[A-Z]+(?![a-z])|[A-Z]?[a-z]+|[0-9]+")


_FIVE_CONSONANTS = re.compile(r"[^aeiouy]{5}")
_VEEAM_GLUE = re.compile(r"D(?:19|20)[0-9]{2}$")
_DATE8 = re.compile(r"(?:19|20)[0-9]{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12][0-9]|3[01])(?:[0-2][0-9][0-5][0-9][0-5][0-9])?")


def _value_like(tok):
    """Whether a run of letters and digits after a secret's name is built like a secret and not like words: 7 or more characters with a digit among them (not the one to four
    digits of a counter at the end), or only digits, or a run of capitals of other than two or three, or a word of lower case letters that is not pronounceable."""
    if len(tok) < 7:
        return False
    tok = _VEEAM_GLUE.sub("", tok)                       # (the D2024 that Veeam glues to a job name before its time stamp)
    if len(tok) < 7:
        return False
    if tok.isdigit():
        return _DATE8.fullmatch(tok) is None             # (a date, 20240312, with or without a time of day, is not a value)
    parts = _WORD_PARTS.findall(tok)
    if parts and parts[-1].isdigit():
        if len(parts[-1]) > 4:
            return True
        parts.pop()
    for n, part in enumerate(parts):
        if part.isdigit():
            return True
        if part.isupper():
            if not 2 <= len(part) <= 3:
                return True
        elif len(part) < 3 or (n > 0 and not part[0].isupper()) or not _word_letters(part):
            return True
    return False


_TECH_WORDS = re.compile("vmware|vcenter|vsphere|vsan|proxmox|nextcloud|splunk|openvpn|pfsense|opnsense|switch|postgres(?:ql)?|pgsql|mysql|mssql|sqlserver|rabbitmq|kafka|"
                         "upgrad(?:e|ed|es|ing)|updat(?:e|ed|es|ing)|workstation|helpdesk|cloudhsm|hyperv|xenserver|netapp|nutanix|veeam|commvault|cohesity|wsus|sccm|pgbouncer|mongodb|redis|"
                         "kubernetes|openshift|jumpbox|gitlab|github|jfrog|zabbix|ldaps?|radius|kerberos|tacacs|cifs|ntnx|qemu|esxi|smtp|sftp|dhcp|https?|iscsi|ntfs|sshd|nightly|monthly|fortnightly|midnight|lightweight|scratch|snmp|crowdstrike|etcd|vmfs|btrfs|openbsd")
_NAME_TOKEN = re.compile(r"[A-Za-z0-9]+")
_TAG = re.compile(r"(?:[a-z]{3,5}|[A-Z]{3,5}|[A-Z][a-z]{2,4})[0-9]{1,4}|[A-Z][0-9][A-Z][0-9]")
_DATE_STAMP = re.compile(r"D?(?:19|20)[0-9]{2}[-_.]?(?:0[1-9]|1[0-2])[-_.]?(?:0[1-9]|[12][0-9]|3[01])(?:[-_.T ]?[0-2][0-9][0-5][0-9][0-5][0-9])?(?:_[0-9A-Fa-f]{4}(?![0-9A-Za-z]))?")


def _word_letters(word):
    """Whether a run of letters reads as a word: every pair of letters is one that words hold (the names of products and services are taken out first), and there are no five consonants in a row."""
    low = _TECH_WORDS.sub("", word.lower())
    for k in range(len(low) - 1):
        if low[k:k + 2] not in _BIGRAMS:
            return False
    return _FIVE_CONSONANTS.search(low) is None


_FILE_EXTS = frozenset(("vmdk", "vmx", "vmsd", "vmsn", "vmem", "vmss", "nvram", "log", "qcow2", "qcow", "vhdx", "avhdx", "vhd", "vdi", "ovf", "ova", "json", "jsonl", "yaml", "conf", "cfg", "flat", "delta", "sesparse", "iso", "img", "raw", "bak", "tmp"))


def _groupish(tok):
    """A run of 4 or more letters and digits that is not a tag (srv01, db02 are tags): the part of a value written in groups (ab12-cd34-ef56)."""
    if len(tok) < 4 or _TAG.fullmatch(tok) is not None:
        return False
    if tok.isalpha() and tok.isupper():
        return _TECH_WORDS.fullmatch(tok.lower()) is None            # (capitals of 4 or more letters are not a word: KHIL, not ESXI)
    if tok.isalpha() and not tok[1:].islower():
        return True                                                  # (a word is not written with a capital in the middle: paUn)
    base = tok.rstrip("0123456789")
    return not (base.isalpha() and len(base) >= 4 and len(tok) - len(base) <= 4 and _word_letters(base))


def _words_value(text, start):
    """Whether any word after a secret's name, from `start` on, is a value: built like a secret by itself, or one of two or more groups in a row (ab12-cd34), which are one value written in parts."""
    tokens = _NAME_TOKEN.findall(_DATE_STAMP.sub(" ", text[start:start + 400]))
    group, run, seen = [], [], False
    for tok in tokens[:40]:
        if _value_like(tok):
            return True
        if tok.lower() in _FILE_EXTS:
            run, seen = [], False                                    # (the end of a file name is not a part of a value)
        elif 4 <= len(tok) <= 6:                                     # (a short word between two groups, or next to one, is part of the value: yIgK-paUn)
            run.append(tok)
            seen = seen or (_groupish(tok) and not tok.isdigit())
            if seen and len(run) >= 2 and _value_like("".join(run)):
                return True
        else:
            run, seen = [], False
        if len(tok) == 5 or len(tok) == 6:
            if tok.isdigit() and tok[0] != "0":
                return True              # 5 or 6 digits that do not start like a counter (000001)
        if _groupish(tok):
            group.append(tok)
            if len(group) >= 2 and _value_like("".join(group)):
                return True
        else:
            group = []
    return False


def _secret_in_ident(text):
    """Whether a name or a path component holds a secret's name with a value after it (see above). Linear: each pattern is anchored on a name and reads at most 400 characters after it."""
    if not _has(_ID_SECRET_WORDS, text.lower()):
        return False
    if _IDENT_FLAG.search(text) is not None or _NAMED_SET.search(text) is not None:
        return True
    for pattern in (_SECRET_THEN, _FLAG_THEN):
        m = pattern.search(text)
        if m is not None and _words_value(text, m.start(1)):
            return True
    return False
_PEM = re.compile(r"-----BEGIN [A-Z0-9 ]{0,40}PRIVATE KEY-----.*?(?:-----END [A-Z0-9 ]{0,40}PRIVATE KEY-----|$)", re.S)
_PREFIX = re.compile(r"(?i:(?:AKIA|ASIA)[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|xox[abeprs]-[A-Za-z0-9-]{10,}|glpat-[A-Za-z0-9_-]{20,}"
                     r"|(?:sk|rk|pk)_(?:live|test)_[A-Za-z0-9]{16,}|SG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}|AIza[0-9A-Za-z_-]{30,}|npm_[A-Za-z0-9]{30,}"
                     r"|dop_v1_[0-9a-f]{40,}|ya29\.[0-9A-Za-z_-]{30,})|sk-(?=[A-Za-z0-9_-]{0,39}[0-9])[A-Za-z0-9_-]{20,}|eyJ[A-Za-z0-9_-]{8,300}\.[A-Za-z0-9_-]{8,}(?:\.[A-Za-z0-9_-]*)?")
_BASE64_PADDED = re.compile(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{16,}={1,2}(?![A-Za-z0-9+=])")
_LONG_DIGITS = re.compile(r"(?<![0-9])[0-9]{19,}(?![0-9])")


_BASE64_PADDED_PATH = re.compile(r"[A-Za-z0-9+/]{22,90}={1,2}(?![A-Za-z0-9+=])")           # (bounded: a long run of these characters costs a step for each of the 90 before a start, not the rest of the run)


def _padded_in_path(field):
    """A padded base64 key that stands behind a `/` (a path ends in the key, or the key's own `/` cut it): the last 22 characters before two pads, 27 before one, are withheld."""
    def sub(m):
        body = m.group().rstrip("=")
        pad = len(m.group()) - len(body)
        keep = len(body) - (22 if pad == 2 else 27)
        if keep < 0:
            return m.group()
        tail = body[keep:]
        if "/" not in tail or len({"d" if c.isdigit() else "u" if c.isupper() else "l" for c in tail if c.isalnum()}) < 2 or not _b64_shape(tail + "=" * pad):
            return m.group()
        return body[:keep] + _b_withheld(tail + "=" * pad, "token-shaped text", field)
    return sub


def _b64_shape(run):
    """Whether a padded run can be base64 of random bytes: its length with the padding is a multiple of 4, and it holds a digit, `+` or `/` (a long
    identifier before an `=` in a line of text, RelatedActivityID=, is not one)."""
    return len(run) % 4 == 0 and re.search(r"[0-9+/]", run) is not None


_NAMED_WORDS = ("pass", "pwd", "secret", "token", "key", "credential", "auth")
_PREFIX_HINTS = ("akia", "asia", "ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_", "xox", "glpat-", "_live_", "_test_", "sg.", "aiza", "npm_", "dop_v1_",
                 "ya29.", "sk-", "eyj")


def _layer2_once(s, field):
    # each rule is tried only when the text holds what it needs (a character or a word it cannot match without): the same result, a lot less reading
    if "withheld" in s:
        s = _MARK_USERINFO.sub(lambda m: m.group("mark") + ":" + _b_withheld(m.group("pw"), "user-info", field), s)
    if "-----" in s:
        s = _outside(s, _MARK, lambda p: _PEM.sub(lambda m: _b_withheld(m.group(), "private key", field), p))
    if "@" in s:
        s = _outside(s, _MARK, lambda p: _URL_USERINFO_SLASH.sub(lambda m: _b_withheld(m.group(), "user-info", field), p))
        s = _outside(s, _MARK, lambda p: _URL_USERINFO.sub(lambda m: _b_withheld(m.group(), "user-info", field), p))
        s = _outside(s, _MARK, lambda p: _B_USERINFO.sub(lambda m: _b_withheld(m.group(), "user-info", field), p))
    low = s.lower()
    if _has(_NAMED_WORDS, low):
        s = _outside(s, _MARK, lambda p: _NAMED.sub(lambda m: m.group()[:m.start("value") - m.start()] + _b_withheld(m.group("value"), "secret value", field), p))
        if "<" in s:
            s = _outside(s, _MARK, lambda p: _PH_SPACE.sub(lambda m: m.group()[:m.start("value") - m.start()] + (_b_withheld(m.group("value"), "secret value", field) if _value_like(m.group("value")) else m.group("value")), p))
            s = _outside(s, _MARK, lambda p: _NAMED_ANGLE.sub(lambda m: m.group()[:m.start("value") - m.start()] + (_b_withheld(m.group("value"), "secret value", field) if any(_value_like(x) for x in _ANGLE_SPLIT.split(m.group("inner"))) else m.group("value")), p))
            s = _outside(s, _MARK, lambda p: _NAMED_PH.sub(lambda m: m.group()[:m.start("value") - m.start()] + _b_withheld(m.group("value"), "secret value", field), p))
    if _has(("pass", "pwd", "secret", "token", "credential", "key"), low):
        s = _outside(s, _MARK, lambda p: _SECRET_THEN_TEXT.sub(lambda m: m.group()[:m.start("value") - m.start()] + (_b_withheld(m.group("value"), "secret value", field) if _value_like(m.group("value")) else m.group("value")), p))
        if "-" in s:
            s = _outside(s, _MARK, lambda p: _GLUED_FLAG.sub(lambda m: m.group()[:m.start("value") - m.start()] + (_b_withheld(m.group("value"), "secret value", field) if _value_like(m.group("value")) else m.group("value")), p))
    if "-" in s or "set" in low or "enable" in low:
        s = _outside(s, _MARK, lambda p: _NAMED_FLAG.sub(lambda m: m.group()[:m.start("value") - m.start()] + _b_withheld(m.group("value"), "secret value", field), p))
        s = _outside(s, _MARK, lambda p: _NAMED_SET.sub(lambda m: m.group()[:m.start("value") - m.start()] + _b_withheld(m.group("value"), "secret value", field), p))
    if "=" in s:
        s = _outside(s, _MARK, lambda p: _BASE64_PADDED.sub(lambda m: _b_withheld(m.group(), "token-shaped text", field) if _b64_shape(m.group()) else m.group(), p))
        if "/" in s:
            s = _outside(s, _MARK, lambda p: _BASE64_PADDED_PATH.sub(_padded_in_path(field), p))
    s = _outside(s, _MARK, lambda p: _LONG_DIGITS.sub(lambda m: _b_withheld(m.group(), "long number", field), p))
    low = s.lower()
    if _has(_PREFIX_HINTS, low):
        s = _outside(s, _MARK, lambda p: _PREFIX.sub(lambda m: _b_withheld(m.group(), "token-shaped text", field), p))
    if "t10." in s or "iqn." in s:
        spans = _t10_hex_spans(s)
        if spans:
            s = _replace_spans(s, _merge(spans), "token-shaped text", field)
    return s


def _outside(text, pattern, fn):
    """`fn` applied to the parts of `text` that `pattern` does not match; the matches are kept as they are."""
    if "withheld" not in text:
        return fn(text)
    out, last = [], 0
    for m in pattern.finditer(text):
        out.append(fn(text[last:m.start()]) if m.start() > last else "")
        out.append(m.group())
        last = m.end()
    out.append(fn(text[last:]) if last < len(text) else "")
    return "".join(out)


def _layer2(s, field):
    out = s
    for _ in range(3):
        nxt = _layer2_once(out, field)
        if nxt == out:
            break
        out = nxt
    return out


# ---- free text: the deny-list ------------------------------------------------------------------------------------------------------
_LABELLED_DIGEST = re.compile(r"(?i)(?:md5|sha-?1|sha-?256|sha-?384|sha-?512|imphash|hashes?|filehash|ssdeep|tlsh)[\"'=:> \t]{1,6}(?:(?:md5|sha-?1|sha-?256|imphash)=)?([0-9a-f]{32,128})")
_TIME = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}[T ][0-9]{2}:[0-9]{2}:[0-9]{2}(?:[.,][0-9]{1,9})?(?:Z|[+-][0-9]{2}:?[0-9]{2})?")
_HEX_RUN = re.compile(r"(?<![0-9A-Za-z])[0-9A-Fa-f]{32,}(?![0-9A-Za-z])")


def _mask_typed(s):
    """A same-length copy of free text in which what is a typed id (GUID, SID, IPv4, time, labelled digest) is `~`."""
    t = s
    if "-" in s:
        t = _GUID.sub(lambda m: "~" * len(m.group()), t)
        if "S-1-" in s:
            t = _SID.sub(lambda m: "~" * len(m.group()), t)
        if ":" in s:
            t = _TIME.sub(lambda m: "~" * len(m.group()), t)
    if "." in s:
        t = _IPV4.sub(lambda m: "~" * len(m.group()), t)
    low = s.lower()
    if _has(_KNOWN_ID_WORDS, low):
        t = _KNOWN_ID.sub(lambda m: "~" * len(m.group()), t)
    if "ash" in low or "md5" in low or "sha" in low:
        t = _LABELLED_DIGEST.sub(lambda m: m.group().replace(m.group(1), "~" * len(m.group(1))), t)
    return t


def _deny_text(s, field):
    t = _mask_typed(s)
    t = t.replace("\x00", " ")
    spans = _bad_runs(t, _JOIN_PATH)
    spans += [m.span() for m in _HEX_RUN.finditer(t)]
    return _replace_spans(s, _merge(spans), "token-shaped text", field) if spans else s


# ---- the entry point for one string ---------------------------------------------------------------------------------------------------
_MEMO = {}


_WIDE_RUN = re.compile(r"[\x20-\x7e\uff01-\uff5e]{4,}")


def _wide_views(raw):
    """Runs of ASCII and full-width ASCII in `raw` read as UTF-8 and as UTF-16LE (at both byte offsets), when it holds a full-width character at
    all: width is folded afterwards (NFKC), so a full-width token written as hexadecimal is read like a plain one."""
    views = []
    if b"\xef\xbc" in raw or b"\xef\xbd" in raw:
        views += _WIDE_RUN.findall(raw.decode("utf-8", "replace"))
    if b"\xff" in raw:
        for offset in (0, 1):
            views += _WIDE_RUN.findall(raw[offset:len(raw) - (len(raw) - offset) % 2].decode("utf-16-le", "replace"))
    return [unicodedata.normalize("NFKC", v) for v in views]


def _hex_views(s):
    """The printable views of binary data written as hex: Latin-1 runs of 6 or more, UTF-16LE and UTF-16BE runs of 4 or more, and the runs that hold
    full-width characters (UTF-8 and UTF-16LE), width folded."""
    try:
        raw = bytes.fromhex(s[: MAX_HEX_JUDGED])
    except ValueError:
        return None
    views = [m.group().decode("latin-1") for m in re.finditer(rb"[\x20-\x7e]{6,}", raw)]
    views += [m.group().decode("utf-16-le", "replace") for m in re.finditer(rb"(?:[\x20-\x7e]\x00){4,}", raw)]
    views += [m.group().decode("utf-16-be", "replace") for m in re.finditer(rb"(?:\x00[\x20-\x7e]){4,}", raw)]
    return views + _wide_views(raw)


def _show_hex(s, field):
    if not s or not re.fullmatch(r"(?:[0-9A-Fa-f]{2})+", s):
        return s if re.fullmatch(r"[0-9A-Fa-f]*", s) else _show_text(s, field)
    if len(s) > MAX_HEX_JUDGED:
        return _b_withheld(s, "binary data over the judged size", field)
    for v in _hex_views(s) or ():
        if _layer2(v, "") != v or _deny_text(v, "") != v or _suspect(v):
            return _b_withheld(s, "binary data holding a secret-shaped text", field)
    return s


def _show_text(s, field):
    # layer 2 reads the string as the evidence wrote it: the deny-list replaces a span and takes with it the context (`user:` of `user:pw@host`, the
    # characters glued before `glpat-`) the position and prefix rules need; what it leaves is read once more
    out = _layer2(s, field)
    denied = _deny_text(out, field)
    return _layer2(denied, field) if denied != out else out


def _show(s, kind, field):
    if s in OWN_NAMES or _MARK.fullmatch(s):
        return s
    if len(s) > MAX_ONE_STRING:
        return _show(s[:MAX_ONE_STRING], kind, field) + _b_withheld(s[MAX_ONE_STRING:], "rest of a long string", field)
    if kind == "id":
        if len(s) <= 3 or _CONTENT_ID.fullmatch(s):
            return s
        for form in _ID_FORMS:
            if _TYPED[form].fullmatch(s) and not (form in _NAMING_IDS and s[:4] in ("t10.", "iqn.") and _bad_runs(s, _JOIN_NAME)):
                return s
        kind = "name"
    if kind in _TYPED:
        if len(s) <= 3 or (_TYPED[kind].fullmatch(s) and not (kind in _NAMING_IDS and s[:4] in ("t10.", "iqn.") and _bad_runs(s, _JOIN_NAME))):
            return s
        return _b_withheld(s, "not a %s" % kind, field)
    if kind == "hex":
        return _show_hex(s, field)
    flat = _flat(s)
    if flat != s:
        # an invisible character, or the escape of one: identifiers fail closed; free text is judged without it
        if kind in ("name", "path", "key", "url"):
            return _b_withheld(s, "invisible characters in a name", field)
        sealed = _show_text(flat, field)
        return sealed if sealed != flat else s
    if kind not in ("name", "path", "key", "url", "host"):
        return _show_text(s, field)
    pre = _layer2(s, field)
    if kind == "name":
        base = _show_name(pre, field)
    elif kind == "path":
        base = _show_path(pre, field)
    elif kind == "key":
        base = _show_key(pre, field)
    elif kind == "url":
        base = _show_url(pre, field)
    else:
        base = _show_host(pre, field)
    return _layer2(base, field) if base != pre else base


def show(s, kind="text", field=""):
    """The text the answer may show for the string `s` of a field of type `kind` (a T carries its own)."""
    if not isinstance(s, str) or not s:
        return s
    kind = getattr(s, "kind", kind)
    memo = (kind, field, s) if len(s) <= 512 and kind not in _TYPED else None            # (a typed id is judged by one match: it is not worth a place in the memo)
    quiet = _QUIET[0]
    if memo is not None:
        hit = _MEMO.get(memo)
        if hit is not None:
            out, pending = hit
            if pending and not quiet:
                # judged earlier only to see what would be printed: it is withheld, counted and written to the values file now that it is printed (once)
                for original, label, where in pending:
                    _b_withheld(original, label, where)
                _MEMO[memo] = (out, None)
            return out
    events = _EVENTS[0] = [] if quiet and memo is not None else None
    try:
        out = _show(str(s), kind, field)
    finally:
        _EVENTS[0] = None
    if memo is not None:
        if len(_MEMO) > 40000:
            _MEMO.clear()
        _MEMO[memo] = (out, events or None)
    return out


_ORDER_SALT = os.urandom(16)


def _quietly(fn):
    """`fn()` with nothing counted, listed or written: judging a string to see what an answer would show of it is not withholding it."""
    saved = (BOUNDARY["withheld"], BOUNDARY["by"].copy(), BOUNDARY["replaced"], BOUNDARY["replaced_by"].copy(), BOUNDARY["where"][:], BOUNDARY["not_listed"], _VALUES["fh"])
    _VALUES["fh"] = None
    was, _QUIET[0] = _QUIET[0], True
    try:
        return fn()
    finally:
        _QUIET[0] = was
        (BOUNDARY["withheld"], BOUNDARY["by"], BOUNDARY["replaced"], BOUNDARY["replaced_by"], BOUNDARY["where"], BOUNDARY["not_listed"], _VALUES["fh"]) = saved


def sealed_text(text, kind="text", field=""):
    """The exact text an answer prints for the string `text` of a field of type `kind`: the layers, then the backstop (a string it replaces comes
    out as its placeholder). Nothing is counted, listed or written to the values file: this is for what must see what the answer shows (a
    `contains` filter, the order of a list)."""
    if not isinstance(text, str) or not text:
        return text
    return _quietly(lambda: _seal(text, kind, field, (), True))


def print_order(items, kind="name", text=str):
    """`items` in the order an answer prints them: by the text the answer PRINTS for each (the layers and the backstop, sealed_text), and the items
    whose text is the same placeholder in a random order that is new for every run. The rank of the withheld texts themselves (the order `sorted`
    would give, the order a directory or a hive lists them in) must never show in what an answer lists. `kind` is the kind of the field the items
    are printed in; `text` gives the string of an item."""
    def judge():
        out = []
        for n, i in enumerate(items):
            raw = text(i)
            shown = _seal(raw, kind, "", (), True) if isinstance(raw, str) and raw else raw
            out.append((shown, hashlib.blake2b(_ORDER_SALT + raw.encode("utf-8", "surrogatepass"), digest_size=8).digest(), n, i))
        return out
    items = list(items)
    keyed = _quietly(judge)
    keyed.sort(key=lambda k: (k[0], k[1], k[2]))
    return [k[3] for k in keyed]


def contains_check(needle_lower, text, kind="text", field=""):
    """(matched, blind) for a `contains` filter: the needle is looked for in the text the answer will PRINT for `text` (sealed_text: after the layers
    AND the backstop), never in what either of them withheld or replaced, so that a count of matches cannot tell a true guess of a hidden piece from
    a wrong one. `blind` is true when it was not found and that text holds a placeholder: the needle may be in what is hidden. It is the same
    whatever the needle, so counting it opens no way to test a guess."""
    sealed = sealed_text(text, kind, field)
    if needle_lower in sealed.lower():
        return True, False
    return False, _MARK.search(sealed) is not None


# ---- layer 3: the backstop, written apart from the layers above ------------------------------------------------------------------------
_S_ESC = re.compile(r"(?<!\\)\\+(?:u([0-9a-fA-F]{4})|U([0-9a-fA-F]{8})|[uU]\{([0-9a-fA-F]{1,8})\}|x([0-9a-fA-F]{2}))")
_S_FILL = "\u115f\u1160\u3164\uffa0\u2800"


def _s_gone(c):
    cat = unicodedata.category(c)
    return cat[0] == "C" or cat in ("Mn", "Me", "Zl", "Zp") or c in _S_FILL


def _s_unesc(m):
    try:
        c = chr(int(m.group(1) or m.group(2) or m.group(3) or m.group(4), 16))
    except (ValueError, OverflowError):
        return m.group(0)
    return "" if _s_gone(c) else m.group(0)


def _s_normal(text):
    if "\\u" in text or "\\U" in text or "\\x" in text:
        text = _S_ESC.sub(_s_unesc, text)
    if text.isascii() and text.isprintable():
        return text
    kept = [c for c in text if not _s_gone(c)]
    return unicodedata.normalize("NFKC", "".join(kept))


_S_PEM = re.compile(r"-----BEGIN [A-Z0-9 ]{0,40}PRIVATE KEY|PRIVATE KEY-----")
_S_DELIM = re.compile(r"[=:]")
_S_NAME_WORDS = ("pass", "pw", "auth", "sig", "sas", "secret", "token", "credential", "key", "psk", "otp", "bearer", "community", "dsn", "pin", "connection_string", "webhook_url")        # a name that ends in a word of _S_STRONG or _S_WEAK holds one of these
_S_FLAGWORD = (r"(?:[a-z0-9]{1,20}[-_]){0,4}(?:passw(?:or)?d|passwd|pass(?:[-_]?phrase)?|pwd|pw|otp|[a-z0-9]{0,20}secret[a-z0-9]{0,20}|[a-z0-9]{0,20}token|api[-_]?key|access[-_]?key|key|keypass|storepass|userpass|auth|authorization|bearer|psk|credentials?|community)")
_S_FLAGCAMEL = r"[A-Za-z0-9]{1,20}(?-i:Key|Token|Password|Passwd|Pwd|Pass|Passphrase|Secret)"
_S_NOVALUE = r"(?!<[^<>\s]{0,40}>(?:[\s;,]|$))(?![A-Za-z0-9_./~:-]{1,120}[.](?i:key|pem|pub|crt|p12|pfx|jks)(?![A-Za-z0-9]))(?!(?:~|[.]{1,2})/[A-Za-z0-9_./-]{1,120}|/[A-Za-z0-9_.-]{1,40}(?:/[A-Za-z0-9_.-]{1,40})+)"
_S_ARGNAME = re.compile(r"(?<![A-Za-z0-9])--?(?i:" + _S_FLAGWORD + r")[= ]" + _S_NOVALUE + r"\S|(?<![A-Za-z0-9])--?" + _S_FLAGCAMEL + r"[= ]" + _S_NOVALUE + r"\S")
_S_PREFIX_WORDS = ("akia", "asia", "agpa", "aida", "aroa", "anpa", "anva", "aipa", "ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_", "glpat-", "xox", "xapp-",
                   "sk_live_", "rk_live_", "pk_live_", "sk_test_", "npm_", "pypi-", "shpat_", "dop_v1_", "aiza", "ya29.", "sg.", "sk-", "eyj")
_S_LINE = re.compile(r"[ \t]*line[ \t]+[0-9]")
_S_NAME_CHARS = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_.-")
_S_STRONG = ("password", "passwd", "passphrase", "passw", "pwd", "secret", "token", "credential", "apikey", "api_key", "api-key", "accesskey", "access_key", "access-key",
             "accountkey", "account_key", "account-key", "privatekey", "private_key", "private-key", "masterkey", "master_key", "sharedkey", "shared_key", "signingkey", "encryptionkey",
             "secretkey", "secret_key", "secret-key")
_S_WEAK = ("pass", "pw", "auth", "sig", "sas")
_S_NOT_PASS = ("bypass", "compass", "overpass", "underpass", "trespass", "encompass", "surpass", "impass")
_S_STRONG_ENDS = tuple(w + p for w in _S_STRONG for p in ("", "s"))       # a name that ends in one of these, or in one of them plural
_S_WEAK_ENDS = tuple(w + p for w in _S_WEAK for p in ("", "s"))
_S_NOT_PASS_ENDS = tuple(w + p for w in _S_NOT_PASS for p in ("", "s"))
_S_VALUEY_ENDS = ("psk", "otp", "bearer", "authorization", "sshkey", "ssh_key", "ssh-key", "snmp_community", "pass_word", "pass-word", "connection_string", "webhook_url", "dsn", "pin")        # names after which only a value built like a secret counts (a log line says `authorization: failed`)
_S_DIGITS = re.compile(r"[0-9]{19}")
_S_HEXRUN = re.compile(r"(?<![0-9A-Za-z])[0-9A-Fa-f]{40,}(?![0-9A-Za-z])")
_S_B64NOPAD = re.compile(r"[A-Za-z0-9+/]{20,}")
_S_B64PADPATH = re.compile(r"[A-Za-z0-9+/]{22,90}={1,2}(?![A-Za-z0-9+=])")
_S_B64PAD = re.compile(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{15,}={1,2}(?![A-Za-z0-9+=])")
# in any case where an upper-case spelling of a lower-case prefix is a likely leak (the vendors' prefixes with a body of 12 or more characters)
_S_PREFIX = re.compile(r"(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA|ANVA|AIPA)[A-Z0-9]{12}|(?i:(?<![A-Za-z0-9])(?:akia|asia)[a-z0-9]{12}|(?:gh[pousr]_|github_pat_|glpat-|xox[a-z]-|xapp-|sk_live_|rk_live_|pk_live_|sk_test_)[A-Za-z0-9_-]{12})"
                       r"|(?:npm_|pypi-|shpat_|dop_v1_|AIza|ya29\.|SG\.)[A-Za-z0-9_-]{12}|sk-(?=[A-Za-z0-9_-]{0,39}[0-9])[A-Za-z0-9_-]{12}|eyJ[A-Za-z0-9_-]{12}")
_S_TOKEN_CHARS = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_.-")
_S_PWHOST = re.compile(r"(?<![A-Za-z0-9._%+-])([A-Za-z0-9]{12,64})@[^\s/@<>\"']")
_S_USERINFO = re.compile(r"[^\s/@:<>\"']{1,64}:(?P<pw>[^\s/<>\"']{1,128})@[^\s/@<>\"']")
_S_USERINFO_MARK = re.compile(r"<>:(?P<pw>[^\s/<>\"']{1,128})@[^\s/@<>\"']")
_S_USERINFO_URL = re.compile(r"(?<=//)(?![^\s/@:<>\"']*:[0-9]{1,5}(?:[/?#@]|$))[^\s/@:<>\"']{1,64}:(?P<pw>[^\s<>\"']{1,128})@[^\s/@<>\"']")
_S_VALUE = re.compile(r"(?:[^\s\"'<>;,&]|[;,&](?![A-Za-z0-9_. -]{1,40}=)){1,512}")
_S_ARGVAL = re.compile(r"(?<![A-Za-z0-9])--?(?:(?i:" + _S_FLAGWORD + r")|" + _S_FLAGCAMEL + r")[= ]" + _S_NOVALUE + r"(\S{1,512})")
# `set password x` and `enable secret x`, and a value glued behind a placeholder (password=<redacted>x, --password <redacted>x, token: <secret>x)
_S_PH_SPACE = re.compile(r"(?:pass|pwd|secret|token|credential|key|auth|psk|otp|pw|sig|sas)[a-z]{0,10}[0-9]{0,2}[\"']?[ \t]{0,2}(?:[=:]|[ \t])[ \t]{0,2}<[^<>\s]{0,40}>[ \t]+([A-Za-z0-9]{8,40})(?![A-Za-z0-9])", re.I)
_S_GLUED = re.compile(r"(?<![A-Za-z0-9])--?(?:[A-Za-z0-9]{1,20}[-_]){0,4}(?:(?i:key|token|pass|password|pwd|secret)|[A-Za-z]{1,20}(?:Key|Token|Pass|Password|Pwd|Secret))([A-Za-z0-9]{8,40})(?![A-Za-z0-9])")
_S_AUTHZ = re.compile(r"(?i:authorization)[\"']?[ \t]{0,2}[=:][ \t]{0,2}[\"']?(?i:token|bearer|basic|negotiate)[ \t]+[A-Za-z0-9+/._~=-]{8,}")
_S_T10TAIL = re.compile(r"t10[.][A-Za-z0-9_.+-]{0,100}?_([A-Za-z]{20,64})(?![A-Za-z0-9])|iqn[.][0-9]{4}-[0-9]{2}[.][a-z0-9.-]{1,60}:([A-Za-z]{20,64})(?![A-Za-z0-9])|iqn[.][0-9]{4}-[0-9]{2}[.]([A-Za-z]{20,64})(?![A-Za-z0-9])")
_S_SET = re.compile(r"(?<![\w-])(?:set|enable)[ \t]+(?:passw(?:or)?d|secret|passphrase|token)[ \t]+(?:[0-9][ \t]+)?[^\s<]", re.I)
_S_ANGLE = re.compile(r"(?:pass|pwd|secret|token|credential|key|auth|psk|otp|pw|sig|sas)[a-z]{0,10}[0-9]{0,2}[\"']?[ \t]{0,2}(?:[=:]|[ \t])[ \t]{0,2}<([A-Za-z0-9+/_.~=-]{6,128})>", re.I)
_S_PH_GLUED = re.compile(r"(?:pass|pwd|secret|token|credential|key|auth|psk|otp|pw|sig|sas)[a-z]{0,10}[0-9]{0,2}[\"']?[ \t]{0,2}(?:[=:]|[ \t])[ \t]{0,2}<[^<>\s]{0,40}>[^\s<>;,&\"']", re.I)
_S_PEMLINE = re.compile(r"[A-Za-z0-9+/=]{12,}")
_S_SHORTRUN = re.compile(r"[A-Za-z0-9]{16,19}")
_S_RUN = re.compile(r"[A-Za-z0-9+/_-]{20,}")
_S_HEX = re.compile(r"[0-9A-Fa-f-]+")
_S_IDS = re.compile(r"\{?[0-9A-Fa-f]{8}-(?:[0-9A-Fa-f]{4}-){3}[0-9A-Fa-f]{12}\}?|[0-9A-Fa-f]{8}-[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}|S-1-[0-9]{1,2}(?:-[0-9]{1,10}){1,15}|[0-9]{4}-[0-9]{2}-[0-9]{2}[T ][0-9:.]+Z?")
_S_MARK = re.compile(r"<withheld [0-9]{1,10} (?:characters|bytes)(?:: [a-z][a-z ,/+-]{0,60}(?:: [a-z][a-z ,/+-]{0,60})?)?>|\[withheld: [0-9]{1,10} (?:characters|bytes)\]")
_S_DIGEST_LABEL = re.compile(r"(?i)(?:md5|sha-?1|sha-?256|sha-?384|sha-?512|imphash|hashes?|filehash|ssdeep|tlsh)[\"'=:> \t]{1,6}(?:(?:md5|sha-?1|sha-?256|imphash)=)?[0-9a-f]{32,128}")
_TYPED_KINDS = frozenset(("guid", "digest", "sid", "mac", "ip", "time", "number", "version", "hex", "label", "vmfs", "device", "iqn", "vmuuid", "cid", "winhost"))
# what a typed field may hold, by the characters of its type (apart from the grammar the first layer checks, and wider than it)
_S_TYPED = {
    "guid": re.compile(r"[0-9A-Fa-f{}-]{1,64}"), "sid": re.compile(r"[Ss0-9-]{1,400}"), "mac": re.compile(r"[0-9A-Fa-f:-]{1,64}"),
    "ip": re.compile(r"[0-9A-Fa-f:.]{1,64}(?:%[0-9A-Za-z_.-]{1,16})?"), "time": re.compile(r"[0-9TtZzDd:.,+' -]{1,64}"),
    "number": re.compile(r"-?[0-9.]{1,64}|0[xX][0-9A-Fa-f]{1,16}|true|false|null"), "version": re.compile(r"(?=.{1,64}\Z)[vV]?[0-9]+(?:\.[0-9A-Za-z]{1,16}){0,6}(?:[-+][0-9A-Za-z.]{1,32}){0,3}"),
    "digest": re.compile(r"(?:sha256:|sha1:|md5:)?[0-9A-Fa-f]{16,128}|T1[0-9A-Fa-f]{16,80}|[0-9]{1,6}:[A-Za-z0-9+/]+:[A-Za-z0-9+/]+"),
    "vmfs": re.compile(r"[0-9A-Fa-f-]{1,40}"), "cid": re.compile(r"[0-9A-Fa-f]{1,16}"), "vmuuid": re.compile(r"[0-9A-Fa-f -]{1,64}"),
    "winhost": re.compile(r"[Ww][Ii][Nn]-[A-Za-z0-9]{1,16}"), "iqn": re.compile(r"iqn\.[0-9A-Za-z.:_-]{1,120}"),
    "device": re.compile(r"(?:naa|eui|vml|t10)\.[A-Za-z0-9_.+-]{1,130}|wwn-0x[0-9A-Fa-f]{1,32}"),
}
_S_LONG = re.compile(r"[A-Za-z0-9+/_-]{19}")           # the shortest run any check below needs (19 digits); the hexadecimal run needs 40, the others 20
_S_PLAIN_NUM = re.compile(r"[0-9TZ:.+ -]+")
_S_HEXONLY = re.compile(r"(?:[0-9A-Fa-f]{2})+")
_S_PRINT_L1 = re.compile(rb"[\x20-\x7e]{6,}")
_S_PRINT_U16 = re.compile(rb"(?:[\x20-\x7e]\x00){4,}")
_S_PRINT_U16BE = re.compile(rb"(?:\x00[\x20-\x7e]){4,}")


def _class(c):
    return 0 if c.isdigit() else 1 if c.isupper() else 2


def _random_run(run, shortest=20):
    if _S_HEX.fullmatch(run):
        return False
    pieces = [p for p in re.split(r"[/_+-]", run) if p]
    alnum = "".join(pieces)
    if len(alnum) < shortest or max(len(p) for p in pieces) < 12:
        return False
    kinds = {_class(c) for c in alnum}
    if len(kinds) < 2:
        return False
    lower = [len(r) for r in re.findall(r"[a-z]+", alnum)]
    if lower and sum(lower) >= 3 * len(lower) and not re.search(r"[A-Z]{2}", alnum):
        return False
    changes = sum(1 for a, b in zip(alnum, alnum[1:]) if _class(a) != _class(b)) / (len(alnum) - 1)
    digit_runs = len(re.findall(r"[0-9]+", alnum))
    if kinds == {0, 1, 2}:
        return changes >= 0.42 or (changes >= 0.3 and digit_runs >= 4 and len(set(alnum)) >= 0.6 * len(alnum))
    if kinds == {1, 2}:
        return changes >= 0.5 and len(alnum) >= 24
    return changes >= 0.4 and digit_runs >= 5 and len(set(alnum)) >= 0.5 * len(alnum)


def _s_letters_random(word):
    """Letters of one case that no word is made of: some pair of them is one that words do not hold (the second check's own test of the serial of a t10. id and the target of an iqn. name)."""
    if not (word.islower() or word.isupper()):
        return False
    low = word.lower()
    return any(low[k:k + 2] not in _BIGRAMS for k in range(len(low) - 1))


def _s_valuey(tok):
    """Whether a run after a placeholder is built like a secret (the second check's own test): a digit among letters that is not a counter at the end, 8 or more digits, or letters with a pair no word holds."""
    body = tok.rstrip("0123456789")
    if not body:
        return len(tok) >= 8
    if len(tok) - len(body) > 4 or any(c.isdigit() for c in body):
        return True
    low = body.lower()
    return any(low[k:k + 2] not in _BIGRAMS for k in range(len(low) - 1)) or re.search("[^aeiouy]{4}", low) is not None


def _s_named(flat, values=None):
    """Whether `flat` holds a value after a secret's name; with a list, the values themselves are added to it (until it holds MAX_PIECES)."""
    pos, found = 0, False
    while True:
        m = _S_DELIM.search(flat, pos)
        if not m or (values is not None and len(values) >= MAX_PIECES):
            return found
        i = m.start()
        pos = m.end()
        after = flat[i + 1:i + 6].lstrip(" \t\"'\\")
        if not after or after[0] in "<>" or _S_LINE.match(flat, i + 1):
            continue
        j = i
        while j > 0 and flat[j - 1] in " \t\"'\\" and i - j < 5:
            j -= 1
        k = j
        while k > 0 and j - k < 64 and flat[k - 1] in _S_NAME_CHARS:
            k -= 1
        low = flat[k:j].lower()
        if low.endswith(_S_STRONG_ENDS) or (low.endswith(_S_WEAK_ENDS) and not low.endswith(_S_NOT_PASS_ENDS)):
            if values is None:
                return True
            found = True
            v = i + 1
            while v < len(flat) and flat[v] in " \t\"'\\" and v - i <= 6:
                v += 1
            vm = _S_VALUE.match(flat, v)
            if vm:
                values.append(vm.group())
        elif low.rstrip("0123456789").endswith(_S_VALUEY_ENDS) or low.rstrip("0123456789").endswith(_S_STRONG_ENDS):
            v = i + 1
            while v < len(flat) and flat[v] in " \t\"'\\" and v - i <= 6:
                v += 1
            vm = _S_VALUE.match(flat, v)
            if vm and _s_valuey(vm.group()):
                if values is None:
                    return True
                found = True
                values.append(vm.group())


def _s_hex_views(text):
    """The printable text inside data written as hexadecimal (Latin-1 runs of 6 or more, UTF-16LE and UTF-16BE runs of 4 or more), or None when `text` is not such data."""
    if len(text) < 2 or not _S_HEXONLY.fullmatch(text[:MAX_HEX_JUDGED]):
        return None
    try:
        raw = bytes.fromhex(text[:MAX_HEX_JUDGED])
    except ValueError:
        return None
    return ([m.group().decode("latin-1") for m in _S_PRINT_L1.finditer(raw)] + [m.group().decode("utf-16-le", "replace") for m in _S_PRINT_U16.finditer(raw)]
            + [m.group().decode("utf-16-be", "replace") for m in _S_PRINT_U16BE.finditer(raw)] + _wide_views(raw))


def _suspect(text, kind="text"):
    """The name of the check a string fails, or None. A string of a typed kind is not tested for runs of hexadecimal digits or random-looking runs, but
    for the characters of its type; data written as hexadecimal is decoded and its printable text is tested as text."""
    if not text or text in OWN_NAMES:
        return None
    if len(text) > MAX_ONE_STRING:
        text = text[:MAX_ONE_STRING]
    if kind == "hex":
        views = _s_hex_views(text)
        if views is not None:
            for view in views:
                hit = _suspect(view, "text")
                if hit:
                    return "in binary data: " + hit
            return None
        kind = "text"
    if kind in _S_TYPED and len(text) <= 64 and _S_PLAIN_NUM.fullmatch(text):
        # digits, `. : + -`, a space, T and Z: no rule above the typed grammar can fire on these (no name, no prefix, no `@`), so the grammar alone decides
        return None if len(text) <= 3 or _S_TYPED[kind].fullmatch(text) else "not the typed grammar"
    flat = _s_normal(text)
    if "withheld" in flat:
        flat = _S_MARK.sub("<>", flat)
    low = flat.lower()
    if "private key" in low and _S_PEM.search(flat):
        return "a PEM marker"
    bare = _S_IDS.sub(" ", flat) if "-" in flat else flat            # (all three kinds of id hold a `-`)
    bare = _mask_embedded(bare)
    named_words = _has(_S_NAME_WORDS, low)
    if named_words and _S_AUTHZ.search(flat):
        return "a named secret"
    if (named_words and ("=" in bare or ":" in bare) and _s_named(bare)) or ("-" in flat and named_words and _S_ARGNAME.search(flat))             or (named_words and "-" in flat and any(_s_valuey(m.group(1)) for m in _S_GLUED.finditer(flat)))             or (named_words and ("<" in flat and (_S_PH_GLUED.search(flat) or any(_s_valuey(x) for m in _S_ANGLE.finditer(flat) for x in _ANGLE_SPLIT.split(m.group(1))) or any(_s_valuey(m.group(1)) for m in _S_PH_SPACE.finditer(flat))) or ("set" in low or "enable" in low) and _S_SET.search(flat))):
        return "a named secret"
    if _has(_S_PREFIX_WORDS, low) and _S_PREFIX.search(flat):
        return "a token prefix"
    if ("t10." in flat or "iqn." in flat) and any(_s_letters_random(m.group(1) or m.group(2) or m.group(3)) for m in _S_T10TAIL.finditer(flat)):
        return "a random-looking run"
    if "@" in flat:
        flat_user = re.sub("(?i)mailto:", "mailto ", flat)
        if _S_USERINFO.search(flat_user) or _S_USERINFO_URL.search(flat_user) or _S_USERINFO_MARK.search(flat_user):       # (the last: a user that was replaced is still a user)
            return "user-info"
        for m in _S_PWHOST.finditer(flat_user):
            word = m.group(1)
            if len({_class(c) for c in word}) == 3 and sum(1 for a, b2 in zip(word, word[1:]) if _class(a) != _class(b2)) >= 0.3 * len(word):
                return "user-info"            # (the password of a user-info whose user was cut off at a colon: a long run of capitals, small letters and digits before the host)
    if kind in _TYPED_KINDS:
        grammar = _S_TYPED.get(kind)
        return "not the typed grammar" if grammar is not None and len(text) > 3 and not grammar.fullmatch(text) else None
    if 16 <= len(bare) <= 19 and _S_SHORTRUN.fullmatch(bare) and _random_run(bare, 16):
        return "a random-looking run"          # (a whole value of 16 to 19 characters: the length of a generated password, as the first layer takes it too)
    if "=" not in bare and not _S_LONG.search(bare):
        return None                       # no run of 19 characters of these, and no `=` for a padded run: none of the checks below can find anything
    if _S_DIGITS.search(bare):
        return "a long digit run"
    labelled = _S_DIGEST_LABEL.sub(" ", bare) if "ash" in low or "sha" in low or "md5" in low else bare
    if _S_HEXRUN.search(labelled):
        return "a long hexadecimal run"
    for m in _S_B64NOPAD.finditer(labelled):
        if "/" in m.group() and "+" in m.group() and len({_class(c) for c in m.group() if c.isalnum()}) == 3:
            return "a base64 run with / and +"
    for m in _S_B64PAD.finditer(labelled):
        body = m.group().rstrip("=")
        if len(m.group()) % 4 == 0 and re.search(r"[0-9+/]", body) and len({_class(c) for c in body}) >= 2 and (("/" in body or "+" in body) or len(body) >= 20):
            return "a padded base64 run"
    if "=" in labelled:
        for m in _S_B64PADPATH.finditer(labelled):
            # a padded key behind the `/` of a path (inputs/Zk0khEa1Ge/Do3O4Hd43iH==): the key is the last 22 (two pads) or 27 (one pad) characters before the padding
            pad = len(m.group()) - len(m.group().rstrip("="))
            tail = m.group().rstrip("=")[-(22 if pad == 2 else 27):]
            if len(tail) >= 22 and "/" in tail and len({_class(c) for c in tail if c.isalnum()}) >= 2:
                return "a padded base64 run"
    for m in _S_RUN.finditer(labelled):
        if _random_run(m.group()):
            return "a random-looking run"
    return None


def _where_text(where, names=True):
    return "/" + "/".join((w[0][:60] if names else str(w[1])) for w in where)


def _replace(value, where, check, positions=False):
    BOUNDARY["replaced"] += 1
    BOUNDARY["replaced_by"][check] += 1
    if len(BOUNDARY["where"]) < MAX_WHERE:
        # the place is the keys on the way, each of them already sealed; their joining is read once more, and when it is not clean the place is the
        # positions (a key that was replaced or withheld must never come back whole through the report of where something was replaced)
        at = _where_text(where, False) if positions else _where_text(where)
        if not positions and _suspect(at, "label"):
            at = _where_text(where, False)
        BOUNDARY["where"].append({"at": at, "check": check})
    else:
        BOUNDARY["not_listed"] += 1
    return _mark(len(value.encode("utf-8", "replace")), "backstop: %s" % check, "bytes")


_CHECKED = {}
_SHORT_PLAIN = re.compile(r"[A-Za-z0-9_.]{0,15}")      # what the late path may print unjudged: 15 characters or fewer of letters, digits, `_` and `.` (no space, no `-`, so no
                                                          # argument after a flag and no `xox?-` token), and not starting like a vendor token (_unjudged)


def _unjudged(text, kind=None):
    """Whether a string may be printed past the judging time: a name this run made itself (OWN_NAMES: its schema keys, its file names), or a short plain
    string that does not start like one of the vendor tokens the block knows (a prefix and 12 characters are 15) and, in a field of a typed kind (a SID, a
    GUID, a digest ...), fits the grammar of that type as the backstop checks it."""
    if text in OWN_NAMES:
        return True
    if _SHORT_PLAIN.fullmatch(text) is None or text.lower().startswith(_S_PREFIX_WORDS):
        return False
    grammar = _S_TYPED.get(kind)
    return grammar is None or len(text) <= 3 or grammar.fullmatch(text) is not None


def _late(n=0):
    """Whether judging must stop for the string about to be judged, which has `n` characters (counted against the cap of the run, unless the string is
    only being judged to see what an answer would print). It says why, once, in _STOP["by"]: the cap of characters, or the clock of the seal."""
    if n and not _QUIET[0]:
        _STOP["chars"] += n
        if _STOP["chars"] > _STOP["cap"]:
            if _STOP["by"] is None:
                _STOP["by"] = "the cap of %d characters judged in one run" % MAX_JUDGED_CHARS
            return True
    deadline = _CLOCK["deadline"]
    if deadline is not None and time.monotonic() > deadline:
        if _STOP["by"] is None:
            _STOP["by"] = "the judging time (the budget of one answer or row, or the seal stop of the tool)"
        return True
    return False


def _stopped(value, where):
    """A string not judged because judging stopped: withheld whole, by its size, counted (what is let through is only _unjudged)."""
    if not _QUIET[0]:
        _STOP["strings"] += 1
    return _replace(value, where, "the judging time ran out", True)


def seal_stop_after(seconds):
    """The seal stop of a tool: no seal runs on past `seconds` from now (its manifest's time limit less 3.5 seconds); what is left is withheld whole,
    except what _unjudged lets through. It stops the judging only, not the tool's own work: that has its own clock, which must run out first."""
    _CLOCK["stop"] = time.monotonic() + seconds


def _timed(fn):
    """`fn()` with the clock of the seal running: SEAL_BUDGET seconds from the outermost call, and never past the seal stop of the tool."""
    first = _CLOCK["deadline"] is None
    if first:
        _CLOCK["deadline"] = time.monotonic() + SEAL_BUDGET
        if _CLOCK["stop"] is not None:
            _CLOCK["deadline"] = min(_CLOCK["deadline"], _CLOCK["stop"])
    try:
        return fn()
    finally:
        if first:
            _CLOCK["deadline"] = None


# the name of a component of the Windows component store (WinSxS), as a whole name or as a component of a key or a path: architecture, words (lower case, letters up
# to 40 or letters and digits up to 16, with `.`, `-` or `_` between them, never a hexadecimal hash), the 16-digit public key token, a four-part version (not always
# there), a language or `none`, and a hash of 8 to 16 hexadecimal digits; a placeholder that layer 1 put in the place of a word, or of the architecture and a word (a
# 32-digit hash), stands for it. A real SOFTWARE hive lists them by the thousand and the backstop took their hash for a random run, so it judges the text with such a
# component taken out; layer 1 judges them as it does every name. Names, keys and paths only, lower case only; every alternative starts with a different character,
# so that a failing match is not retried in a second way.
_WORD = r"(?:[a-z]{1,40}|(?=[a-z0-9]*[0-9])[a-z0-9]{1,16}|<withheld [0-9]{1,10} (?:characters|bytes): not a plain name>)"
_WINSXS = re.compile(r"(?<![^\\/])(?:(?:amd64|x86|wow64|msil|arm64|arm|ia64)_(?![0-9a-f]+_)%s(?:[._-]{1,3}%s){0,12}|<withheld [0-9]{1,10} (?:characters|bytes): not a plain name>)"
                     r"_[0-9a-f]{16}(?:_[0-9]{1,5}(?:\.[0-9]{1,5}){3})?_[a-z0-9-]{2,12}_[0-9a-f]{8,16}(?![^\\/])" % (_WORD, _WORD))


def _without_components(text, kind):
    """`text` as the backstop judges a name, key or path: a component of the component store is one plain word."""
    return _WINSXS.sub("w", text) if kind in ("name", "key", "path") and text.count("_") >= 3 else text


def _verdict(text, kind):
    memo = (kind, text) if len(text) <= 512 and kind not in _S_TYPED else None
    hit = _CHECKED.get(memo, False) if memo else False
    if hit is False:
        hit = None if _MARK.fullmatch(text) else _suspect(_without_components(text, kind), kind)
        if memo:
            if len(_CHECKED) >= 30000:
                _CHECKED.clear()
            _CHECKED[memo] = hit
    return hit


# ---- the backstop reads the original too: what of a secret-shaped text is still in what was shown
def _pem_pieces(flat, found):
    """The base64 lines of the bodies of PEM keys: after each `PRIVATE KEY-----` (found with str.find, at most MAX_PIECES of them) up to the next
    `-----END` or MAX_PEM_BODY characters."""
    pos, bodies = 0, 0
    while bodies < MAX_PIECES and len(found) < MAX_PIECES:
        i = flat.find("PRIVATE KEY-----", pos)
        if i < 0:
            return
        start = i + 16
        end = flat.find("-----END", start, start + MAX_PEM_BODY)
        stop = start + MAX_PEM_BODY if end < 0 else end
        bodies += 1
        for m in _S_PEMLINE.finditer(flat, start, stop):
            found.append(m.group())
            if len(found) >= MAX_PIECES:
                return
        pos = max(stop, start)


def _s_pieces(flat, kind):
    """The parts of `flat` (the original text, normalised) the backstop's own rules call secret: a value after a secret's name, the password of
    user-info, a vendor token, a key's base64, and (outside typed fields) the long random-looking runs. At most MAX_PIECES of them, in this
    order; every walk over the text stops when the list is full."""
    found = []
    bare = _S_IDS.sub(" ", flat)
    _s_named(bare, found)
    for pattern, group in ((_S_ARGVAL, 1), (_S_USERINFO, "pw"), (_S_USERINFO_URL, "pw")):
        for m in pattern.finditer(flat):
            if len(found) >= MAX_PIECES:
                return found
            found.append(m.group(group))
    for m in _S_PREFIX.finditer(flat):
        if len(found) >= MAX_PIECES:
            return found
        end = m.end()
        stop = min(len(flat), end + 512)
        while end < stop and flat[end] in _S_TOKEN_CHARS:
            end += 1
        found.append(flat[m.start():end])
    _pem_pieces(flat, found)
    if kind not in _TYPED_KINDS:
        labelled = _S_DIGEST_LABEL.sub(" ", bare) if "ash" in bare or "sha" in bare.lower() or "md5" in bare.lower() or "ASH" in bare else bare
        for m in _S_B64PAD.finditer(labelled):
            if len(found) >= MAX_PIECES:
                return found
            if _b64_shape(m.group()):
                found.append(m.group())
        for m in _S_HEXRUN.finditer(labelled):
            if len(found) >= MAX_PIECES:
                return found
            found.append(m.group())
        for m in _S_B64NOPAD.finditer(labelled):
            if len(found) >= MAX_PIECES:
                return found
            if "/" in m.group() and "+" in m.group():
                found.append(m.group())
        for m in _S_RUN.finditer(labelled):
            if len(found) >= MAX_PIECES:
                return found
            if _random_run(m.group()):
                found.append(m.group())
    return found


_RESIDUE = {}


def _residue_worthy(win):
    """Whether a window of a piece is a secret's and not the words of a path the piece ran into (a run of base64 characters takes in `/vmfs/volumes/ds1/` before a key): a window with a `/` needs 3 capitals, digits or `+`."""
    return "/" not in win or sum(1 for c in win if c.isupper() or c.isdigit() or c == "+") >= 3


def _residue(original, shown, kind):
    """A window of 12 characters (the whole piece when it is shorter, from 8) of something the backstop calls secret in the ORIGINAL that is still
    in what was shown: the layers above cut spans out of a string and can leave a piece of a secret between two cuts."""
    memo = (kind, original) if len(original) <= 512 else None
    if memo is not None and memo in _RESIDUE:
        return _RESIDUE[memo]
    verdict = None
    flat = _s_normal(original[:MAX_ONE_STRING])
    pieces = _s_pieces(flat, kind)[:MAX_PIECES]
    if pieces:
        kept = _S_MARK.sub("\x00", _s_normal(shown[:MAX_ONE_STRING]))
        rest = flat                                    # the original without those parts: a window that is also here is the text's own words, not the secret
        for piece in sorted(set(pieces), key=len, reverse=True):
            rest = rest.replace(piece, "\x00")
        for piece in pieces:
            n = len(piece)
            if n < 8:
                continue
            w = min(12, n)
            step = 1 if n * len(kept) <= 4000000 else max(1, (n - w + 1) // 64)       # a long piece in a long string: 64 windows, spread over it
            if any(piece[i:i + w] in kept and piece[i:i + w] not in rest and _residue_worthy(piece[i:i + w]) for i in range(0, n - w + 1, step)):
                verdict = "a part of a secret-shaped text"
                break
    if memo is not None:
        if len(_RESIDUE) >= 30000:
            _RESIDUE.clear()
        _RESIDUE[memo] = verdict
    return verdict


# ---- the walker ----------------------------------------------------------------------------------------------------------------------------
_SCALARS = (bool, int, float)
_SCALAR_TYPES = frozenset(_SCALARS)


_KEYS = {}


def _seal(value, kind, field, where, guard, fname=""):
    """`value` with every string sealed by the type of its field, and (guard) read back by the backstop. Keys are names. FIELDS maps a JSON key to the
    kind of what it holds, or to a function of the key of one item for a dict whose items have kinds of their own (event data, registry values).
    `where` is the tuple of (sealed key or position, position) on the way down."""
    if isinstance(value, str):
        k = getattr(value, "kind", kind)
        if _late(len(value)):
            # past the budget the rest is withheld whole, fail closed; what is let through is only a name of this run's own and a short plain string (_unjudged)
            return value if _unjudged(value, k) else _stopped(value, where)
        out = show(value, k, field)
        if guard:
            check = _verdict(out, k)
            if not check and out != value:
                check = _residue(str(value), out, k)
            if check:
                return _replace(out, where, check)
        return out
    if value is None or isinstance(value, _SCALARS):
        return value
    if isinstance(value, dict):
        hook = _field_entry(fname)
        hook = hook if callable(hook) else None
        kk = KEY_KINDS.get(fname, "name")
        out, dupes = {}, {}
        for idx, (key, v) in enumerate(value.items()):
            if isinstance(key, str):
                if _late(len(key)):
                    sk = key if _unjudged(key) else _stopped(key, where + (("(key)", idx),))
                else:
                    sk = _KEYS.get((kk, field, key, guard))
                    if sk is None:
                        sk = show(key, kk, field)
                        if guard:
                            check = _verdict(sk, kk)
                            if check:
                                sk = _replace(sk, where + (("(key)", idx),), check)
                        if sk == key and len(key) <= 128:
                            # a key that comes out as it went in changed nothing (no count, no list): its judging is not repeated for the next row
                            if len(_KEYS) >= 20000:
                                _KEYS.clear()
                            _KEYS[(kk, field, key, guard)] = sk
            elif key is None or isinstance(key, _SCALARS):
                sk = key
            else:
                key = str(key)
                sk = show(key, "name", field)
            if sk in out:
                # many names become one placeholder: the next free " #n" of that placeholder, counted (a probe from the first would be quadratic)
                n = dupes.get(sk, 1)
                while True:
                    n += 1
                    renamed = "%s #%d" % (sk, n)
                    if renamed not in out:
                        break
                dupes[sk] = n
                sk = renamed
            if v is None or type(v) in _SCALAR_TYPES:
                out[sk] = v                               # (a number, a truth value or nothing: there is no string to seal)
                continue
            fk = key if isinstance(key, str) else ""
            sub_kind = (hook(key) if hook else None) or _kind_of(fk, kind)
            label = sk if isinstance(sk, str) else str(sk)
            out[sk] = _seal(v, sub_kind, (field + "." + fk) if field and fk else (fk or field), where + ((label, idx),), guard, fk)
        return out
    if isinstance(value, (list, tuple)):
        return [_seal(v, kind, field, where + ((str(i), i),), guard, fname) for i, v in enumerate(value)]
    return _seal(str(value), "text", field, where, guard, fname)       # anything else the serialiser would have printed with str()


def _kind_of(field, inherited):
    k = _field_entry(field)
    return k if isinstance(k, str) else inherited


def seal(value, kind="text", field=""):
    return _timed(lambda: _seal(value, kind, field, (), True))


_ROW_TYPES = frozenset((str, int, float, bool))
_ROW = [None, None]             # the last row of plain scalars that was sealed without anything being replaced, and what it came out as


def row_object(row):
    """A row of a paging file, sealed and read back: what the file may hold. A tool that writes the same row to two files (every key listed, and
    the nodes of a walk) has it judged once: the second is the first's result, the same judging with nothing to count or list."""
    key = None
    if isinstance(row, dict):
        for k, v in row.items():
            if type(k) is not str or (v is not None and type(v) not in _ROW_TYPES):
                break
        else:
            # (the type is part of the key: 1, True and 1.0 are equal and print differently; a float by its repr, as -0.0 equals 0.0)
            key = tuple((k, type(v), repr(v) if type(v) is float else v) for k, v in row.items())
    if key is not None and _ROW[0] == key:
        return dict(_ROW[1])
    replaced = BOUNDARY["replaced"]
    out = _timed(lambda: _seal(row, "text", "", (), True))
    if key is not None and BOUNDARY["replaced"] == replaced:
        _ROW[0], _ROW[1] = key, dict(out)
    return out


def boundary_summary():
    stopped = {"stopped_by": _STOP["by"], "strings_withheld_by_the_stop": _STOP["strings"]} if _STOP["by"] is not None else {}
    return {"strings_withheld": BOUNDARY["withheld"], "withheld_by_reason": dict(BOUNDARY["by"]),
            "strings_replaced_by_the_backstop": BOUNDARY["replaced"], "replaced_by_check": dict(BOUNDARY["replaced_by"]),
            "replaced_at": list(BOUNDARY["where"]), "replaced_not_listed": BOUNDARY["not_listed"], "values": values_summary(), **stopped,
            "note": "every key and value of this answer and of its paging files was judged by the type of its field: a name, path, key or URL is shown only when it "
                    "fits a plain grammar (a path component by component), free text has token-shaped runs, user-info and the value after a secret's name withheld, "
                    "and a second check written apart from both read it back. A withheld text is <withheld N characters: reason>. Not recognised: a secret that does "
                    "not look like one (a plain password or passphrase, a UUID-shaped key, anything under 16 characters in a name)."}


def _last_look(obj):
    """What this block adds to an answer after the walker (the report of what it did) is read once more by the backstop, keys and values."""
    if isinstance(obj, str):
        return _mark(len(obj), "backstop: a part of a secret-shaped text") if _suspect(obj, "label") else obj
    if isinstance(obj, dict):
        return {_last_look(k): _last_look(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_last_look(v) for v in obj]
    return obj


def answer_object(doc):
    """The answer (or an error answer), sealed and read back. A string the backstop had to replace makes a complete answer partial."""
    _STOP["cap"] = max(_STOP["cap"], _STOP["chars"]) + FINAL_GRACE_CHARS            # (the final answer is always judged: the cap of the run does not take it)
    out = _timed(lambda: _seal(doc, "text", "", (), True))
    if isinstance(out, dict):
        out["boundary"] = _last_look(boundary_summary())
        if (BOUNDARY["replaced"] > 0 or _STOP["by"] is not None) and out.get("status") == "complete":
            out["status"] = "partial"
            basis = out.get("status_basis")
            why = []
            if BOUNDARY["replaced"] > 0:
                why.append("%d string(s) still held a secret-shaped text when the answer was checked on its way out and were replaced" % BOUNDARY["replaced"])
            if _STOP["by"] is not None:
                why.append("judging the strings stopped at %s: %d string(s) after it were withheld by their size" % (_STOP["by"], _STOP["strings"]))
            out["status_basis"] = "%s%s (see boundary)" % (basis + "; " if isinstance(basis, str) and basis else "", "; ".join(why))
    return out


def emit(doc, **dumps_kwargs):
    """Print an answer through the boundary (the only way an answer leaves a tool that carries this block)."""
    obj = answer_object(doc)
    try:
        text = json.dumps(obj, ensure_ascii=False, default=str, **dumps_kwargs)
        text.encode("utf-8")
    except UnicodeEncodeError:
        text = json.dumps(obj, ensure_ascii=True, default=str, **dumps_kwargs)
    try:
        # a signal that arrives while the answer is being written must not start a second one: signals are held from here (the answer is whole)
        signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGTERM, signal.SIGINT, signal.SIGHUP})
    except (AttributeError, ValueError, OSError):
        pass
    print(text, flush=True)
# END SHARED BOUNDARY


# ---- this tool's own part ------------------------------------------------------------------------------------------------------------

NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
PARSER = "powershell_blocks/1"
DEADLINE_SECONDS = 54             # the manifest allows 60; the seal stop (56.5) is 2.5 seconds later
READ_SECONDS = 36                 # reading stops here, so that the files and the answer are made inside the run's own clock
OUTPUT_SECONDS = 48               # listing the blocks stops here (the rows are judged one by one, which costs time in proportion to their number)
FILE_MAGIC = b"ElfFile\x00"
MAX_FRAGMENTS = 200000            # fragments kept (metadata only: the text is never held)
MAX_BLOCKS = 100000
MAX_KEY = 256                     # characters of a Computer or a ScriptBlockId that are grouped on (a longer one is not a name of either)
MAX_PATH = 32768                  # characters of a Path value that are listed
PATH_BUDGET = 32 << 20            # characters of Path values listed in all
PATHS_PER_BLOCK = 16
MAX_LINE = 16 << 20               # bytes of one JSON Lines row that are read
MAX_PROBLEM_ROWS = 2000
INLINE_RECORDS = 50               # a block with more fragments than this lists its records only in the fragments file
LISTED = 50                       # ranges and duplicate numbers listed per block (the counts are whole)
CHANNELS = {"microsoft-windows-powershell/operational": "windows_powershell", "powershellcore/operational": "powershell_core"}
WHOLE = re.compile(r"^[0-9]{1,10}$")
LEVEL = re.compile(r"<Level>([0-9]{1,3})</Level>")
FP_KEY = os.urandom(32)           # for this run only: fragments are compared with it in memory, and nothing derived from it is written or printed
STARTED = time.monotonic()

OWN_NAMES.update((
    "all_problems", "arrival", "auto_logged_warning", "block", "block_count", "block_status", "blocks", "blocks_by_source", "blocks_by_status", "blocks_file",
    "channel", "chunk_offset", "chunks_declared", "chunks_in_file", "chunks_not_read", "chunks_read", "complete", "computer", "conflict", "duplicate_numbers",
    "duplicates", "error", "expected_fragments", "file_bytes", "fragment_count", "fragments_file", "channels", "blocks_listed", "blocks_not_listed", "fragments_kept", "fragments_malformed",
    "fragments_not_kept", "fragments_text_withheld_upstream", "fragments_with_unpaired_surrogates", "gaps", "header_dirty", "header_flags", "input_format",
    "levels", "lines_too_long", "level", "message_number", "message_total", "message_totals", "missing_count", "missing_ranges", "missing_ranges_total",
    "note", "numbers_distinct", "numbers_out_of_range", "other", "parse_errors", "parser", "path", "paths", "paths_not_listed", "powershell_core",
    "problem_count", "problems", "reason", "record_id", "record_offset", "records", "records_4104", "records_examined", "records_other_events", "records",
    "returned", "same_text", "same_text_as_first", "script_block_id", "signal", "source", "status", "status_basis", "stopped_by_time", "text_blocks_not_written",
    "text_bytes", "text_file", "text_length", "text_withheld_upstream", "text_written", "truncated", "unequal_copies", "why", "interrupted", "windows_powershell",
    "evtx", "jsonl", "line", "lines_read", "numbers_joined", "text", "slots_empty_beyond_declared", "blocks_not_kept"
))
FIELDS.update({
    "path": "path", "blocks_file": "path", "fragments_file": "path", "text_file": "path", "all_problems": "path", "paths": "path",
    "channel": "key", "computer": "host", "script_block_id": "guid",
})

# The signals are cooperative (see the EVTX READ block): they are in from here on, so that a stop that comes while the rest of the module is
# still being read is answered at the first check.
install_signal_handlers()

TEMPS = []                        # hidden temporary files of this run that are not a page's (the spool, the text file being written): removed on any way out


class SealedPage(NoReplacePage):
    """A page whose rows are written through the boundary."""

    def _write(self, row):
        super()._write(row_object(row))

    def finish(self):
        result = super().finish()
        if result.get("all_results"):
            OWN_NAMES.add(result["all_results"])             # the name of a result file is this tool's own: the answer keeps it readable past the judging time
        return result


class CompletePage(SealedPage):
    """A page whose whole result is ALWAYS kept in a file (LosslessPage writes the file only when there are more rows than the page)."""

    def finish(self) -> dict:
        if self._out is None and self.page:
            try:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                fd, name = tempfile.mkstemp(dir=self.path.parent, prefix=f".{self.path.name}-")
                self._tmp = Path(name)
                self._out = os.fdopen(fd, "w", encoding="utf-8")
            except OSError as exc:
                self._cannot_write(exc)
            for kept in self.page:
                self._write(kept)
        return super().finish()


class ResultWriteError(Exception):
    """A file of this run could not be written: not a record that failed to parse."""


def cleanup():
    """Every hidden temporary file of this run goes: a page's that was being written, the spool, a text file not yet placed."""
    for page in list(PAGES):
        out, page._out = getattr(page, "_out", None), None
        try:
            if out is not None:
                out.close()
        except BaseException:
            pass
        tmp = getattr(page, "_tmp", None)
        if tmp is not None:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            page._tmp = None
    for name in list(TEMPS):
        try:
            os.unlink(name)
        except OSError:
            pass
    del TEMPS[:]


def fail(message, **extra):
    cleanup()
    close_values()
    emit({"error": message, "status": "failed", "status_basis": "the tool stopped with an error (see error); no block was reassembled", **extra})
    raise SystemExit(1)


def whole(args, name, default, low):
    v = args.get(name)
    if v is None:
        return default
    if isinstance(v, bool) or not isinstance(v, int) or v < low:
        fail("%s must be a whole number of at least %d" % (name, low), **{name: args.get(name) if isinstance(v, (int, float)) and not isinstance(v, bool) else None})
    return v


def flag(args, name):
    v = args.get(name, False)
    if v is None:
        return False
    if not isinstance(v, bool):
        fail("%s must be true or false" % name)
    return v


def text_refused():
    """write_text is decided before anything is opened or created: the reassembled text is a secret output, written only in a job the harness runs as one."""
    return not (os.environ.get("JOB_ID") and os.environ.get("OUT") and os.environ.get("SECRET_OUTPUT") == "1")


def source_of(channel):
    return CHANNELS.get(channel.strip().lower(), "other")


def event_from_xml(xml):
    """The fields of one event the blocks are made from. A document type declaration in the XML is never parsed."""
    if "<!DOCTYPE" in xml or "<!ENTITY" in xml:
        raise ValueError("the record's XML has a document type declaration and was not parsed")
    root = ET.fromstring(xml)
    system = root.find("e:System", NS)
    ev = {"event_id": None, "channel": "", "computer": "", "record_id": None, "level": None, "data": {}}
    if system is not None:
        try:
            ev["event_id"] = int(system.findtext("e:EventID", default="", namespaces=NS))
        except ValueError:
            pass
        try:
            ev["record_id"] = int(system.findtext("e:EventRecordID", default="", namespaces=NS))
        except ValueError:
            pass
        ev["channel"] = system.findtext("e:Channel", default="", namespaces=NS) or ""
        ev["computer"] = system.findtext("e:Computer", default="", namespaces=NS) or ""
        level = (system.findtext("e:Level", default="", namespaces=NS) or "").strip()
        ev["level"] = int(level) if WHOLE.match(level) else None
    section = root.find("e:EventData", NS)
    if section is not None:
        for node in section.iterfind("e:Data", NS):
            name = node.get("Name")
            if name is None:
                continue
            value = node.text or ""
            old = ev["data"].get(name)
            ev["data"][name] = value if old is None else (old + [value] if isinstance(old, list) else [old, value])
    return ev


def event_from_row(row):
    """The same fields from a row of evtx_query: its `data` (EventData names to text), or its XML when it has no data."""
    if not isinstance(row, dict):
        raise ValueError("the line is not a JSON object")
    xml = row.get("xml") if isinstance(row.get("xml"), str) else None
    data = row.get("data")
    if isinstance(data, dict):
        ev = {"event_id": row.get("event_id"), "channel": row.get("channel"), "computer": row.get("computer"), "record_id": row.get("record_id"),
              "level": None, "data": data}
        if xml is not None:
            m = LEVEL.search(xml)
            ev["level"] = int(m.group(1)) if m else None
    elif xml is not None:
        ev = event_from_xml(xml)
        if ev["event_id"] is None:
            ev["event_id"] = row.get("event_id")
    else:
        raise ValueError("the row has neither data nor xml")
    for key in ("event_id", "record_id"):
        v = ev[key]
        if v is not None and (isinstance(v, bool) or not isinstance(v, int)):
            ev[key] = None
    for key in ("channel", "computer"):
        if not isinstance(ev[key], str):
            ev[key] = ""
    return ev


class Blocks:
    """The fragments of the log, as metadata: the text of a fragment is never held (only its length, and a keyed value to compare copies in memory;
    with write_text the text goes to a spool file under $OUT, mode 0600, and is read back from there)."""

    def __init__(self, spool):
        self.groups = {}                  # (source, computer, script block id) -> {"frags": [...], "paths": [...], "path_extra": 0, "channels": set()}
        self.spool = spool
        self.spool_at = 0
        self.arrival = 0
        self.kept = 0
        self.c = {"examined": 0, "other_events": 0, "records_4104": 0, "not_kept_fragments": 0, "not_kept_blocks": 0, "malformed": 0, "withheld_upstream": 0,
                  "surrogates": 0, "paths_not_listed": 0, "path_chars": 0, "parse_errors": 0, "problems": 0, "lines_too_long": 0}

    def add(self, ev, where, problem):
        """One event; `where` (a record offset, a chunk offset, a line) says where it came from, for a problem."""
        c = self.c
        c["examined"] += 1
        if ev["event_id"] != 4104:
            c["other_events"] += 1
            return
        c["records_4104"] += 1
        data = ev["data"]
        number, total, sbid = data.get("MessageNumber"), data.get("MessageTotal"), data.get("ScriptBlockId")
        text, path = data.get("ScriptBlockText", ""), data.get("Path", "")
        computer = ev["computer"]
        if not all(isinstance(v, str) for v in (number, total, sbid, text, path)):
            c["malformed"] += 1
            problem("a 4104 record without a usable MessageNumber, MessageTotal or ScriptBlockId (or with one of its fields twice) was not grouped", where)
            return
        number, total = number.strip(), total.strip()
        if not WHOLE.match(number) or not WHOLE.match(total) or not sbid.strip() or len(sbid) > MAX_KEY or len(computer) > MAX_KEY:
            c["malformed"] += 1
            problem("a 4104 record whose MessageNumber or MessageTotal is not a whole number, or whose ScriptBlockId is empty or longer than %d characters, "
                    "or whose Computer is longer than %d, was not grouped" % (MAX_KEY, MAX_KEY), where)
            return
        key = (source_of(ev["channel"]), computer, sbid)
        group = self.groups.get(key)
        if (group is None and len(self.groups) >= MAX_BLOCKS) or self.kept >= MAX_FRAGMENTS:
            c["not_kept_fragments"] += 1
            if group is None and len(self.groups) >= MAX_BLOCKS:
                c["not_kept_blocks"] += 1
            return
        if group is None:
            group = self.groups[key] = {"frags": [], "paths": [], "path_extra": 0, "channels": set()}
        flags = 0
        try:
            raw = text.encode("utf-8")
        except UnicodeEncodeError:
            raw = text.encode("utf-8", "surrogatepass")          # a lone surrogate (text that was not UTF-8): kept, and counted
            flags |= 1
            c["surrogates"] += 1
        if _MARK.search(text):
            flags |= 2
            c["withheld_upstream"] += 1
        spooled = -1
        if self.spool is not None:
            try:
                self.spool.write(raw)
            except OSError as exc:
                raise ResultWriteError(str(exc))
            spooled = self.spool_at
            self.spool_at += len(raw)
        fp = hmac.new(FP_KEY, raw, "sha256").digest()[:8]
        self.arrival += 1
        self.kept += 1
        group["frags"].append((int(number), int(total), self.arrival, ev["record_id"], where.get("record_offset"), where.get("chunk_offset"), len(text), fp,
                               ev["level"], spooled, len(raw), flags))
        if len(group["channels"]) < 4:
            group["channels"].add(ev["channel"])
        if path and path not in group["paths"]:
            if len(group["paths"]) >= PATHS_PER_BLOCK or len(path) > MAX_PATH or c["path_chars"] + len(path) > PATH_BUDGET:
                group["path_extra"] += 1
                c["paths_not_listed"] += 1
            else:
                group["paths"].append(path)
                c["path_chars"] += len(path)


def analyse(frags):
    """What the fragments of one block say about the block. Linear in the fragments after the sort."""
    order = sorted(frags, key=lambda f: (f[0], f[2]))
    totals = sorted({f[1] for f in order})
    levels = sorted({f[8] for f in order if f[8] is not None})
    expected = totals[0] if len(totals) == 1 else None
    distinct = out_of_range = 0
    missing = []                      # [low, high] ranges of the numbers 1..expected that no fragment has
    dups = []                         # [number, records, same_text]
    firsts = []                       # the first fragment (by arrival) of each number, in number order
    previous = 0
    i, n = 0, len(order)
    while i < n:
        number = order[i][0]
        j = i
        while j < n and order[j][0] == number:
            j += 1
        distinct += 1
        first = order[i]
        firsts.append(first)
        if expected is not None:
            if number < 1 or number > expected:
                out_of_range += 1
            else:
                if number > previous + 1:
                    missing.append([previous + 1, number - 1])
                previous = number
        if j - i > 1:
            dups.append([number, j - i, all(c[6] == first[6] and c[7] == first[7] for c in order[i + 1:j])])
        i = j
    if expected is not None and previous < expected:
        missing.append([previous + 1, expected])
    missing_count = sum(b - a + 1 for a, b in missing)
    unequal = sum(1 for d in dups if not d[2])
    if expected is None or out_of_range or unequal:
        status = "conflict"
    elif missing_count:
        status = "gaps"
    else:
        status = "complete"
    return {"order": order, "firsts": firsts, "totals": totals, "levels": levels, "expected": expected, "distinct": distinct, "out_of_range": out_of_range,
            "missing": missing, "missing_count": missing_count, "dups": dups, "unequal": unequal, "status": status}


def open_regular(path):
    """The file, opened without waiting on it (a FIFO or a device would hold the tool), and looked at before a byte is read."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0))
    except (OSError, ValueError) as exc:
        fail("the file could not be opened", path=path, reason=getattr(exc, "strerror", None) or type(exc).__name__)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            os.close(fd)
            fail("the path is not a regular file, so it was not read", path=path, not_attempted=1)
    except OSError as exc:
        os.close(fd)
        fail("the file could not be examined", path=path, reason=exc.strerror or type(exc).__name__)
    return os.fdopen(fd, "rb")


def read_evtx(fh, file_bytes, blocks, problem, over):
    """Every chunk slot of the file, read with the code of the EVTX READ block; the events go to `blocks`. Returns the report of the file."""
    from Evtx.Evtx import ChunkHeader
    c = blocks.c
    head = fh.read(0x80)
    header_bytes = struct.unpack_from("<H", head, 0x28)[0] if len(head) >= 0x2A else 0
    if header_bytes < 0x80 or header_bytes > CHUNK_SIZE:
        problem("the file header names a header size of %d bytes: 4096 is taken" % header_bytes, {})
        header_bytes = 0x1000
    declared = struct.unpack_from("<H", head, 0x2A)[0] if len(head) >= 0x2C else None
    flags = struct.unpack_from("<I", head, 0x78)[0] if len(head) >= 0x7C else None
    slots = (file_bytes - header_bytes) // CHUNK_SIZE if file_bytes > header_bytes else 0
    report = {"chunks_declared": declared, "chunks_in_file": slots, "chunks_read": 0, "chunks_not_read": 0, "header_flags": flags,
              "header_dirty": bool(flags & 1) if flags is not None else None, "stopped_by_time": False, "slots_empty_beyond_declared": 0}
    if declared is not None and file_bytes < header_bytes + declared * CHUNK_SIZE:
        problem("the file is %d bytes and its header declares %d chunks, which take %d: the log is cut short" % (file_bytes, declared, header_bytes + declared * CHUNK_SIZE), {})

    def read_chunk(chunk):
        items = []
        try:
            with chunk_guard():
                for rec in chunk.records():
                    try:
                        items.append(("record", rec.offset(), rec.xml(), None))
                    except Exception as exc:
                        items.append(("record_error", None, None, str(exc)))
        except ChunkTimeout:
            items.append(("timeout", None, None, None))
        except Exception as exc:
            items.append(("chain", None, None, str(exc)))
        return items

    for index in range(slots):
        check_stop()
        if out_of_time() or over():
            report["stopped_by_time"] = True
            problem("the clock of the run ran out after chunk %d of %d: the chunks after it were not read" % (index, slots), {})
            break
        chunk_offset = header_bytes + index * CHUNK_SIZE
        fh.seek(chunk_offset)
        raw = fh.read(CHUNK_SIZE)
        beyond = declared is not None and index >= declared
        if raw[:len(CHUNK_MAGIC)] != CHUNK_MAGIC:
            if beyond:
                report["slots_empty_beyond_declared"] += 1
            else:
                report["chunks_not_read"] += 1
                problem("a chunk the file header declares has no ElfChnk signature and was not read", {"chunk_offset": chunk_offset})
            continue
        refusal = reject_signature(raw[:HEADER_BYTES]) if beyond else None
        if refusal is None:
            refusal = chain_problem(raw)
            if refusal is not None:
                refusal = "its %s" % refusal
        if refusal is not None:
            report["chunks_not_read"] += 1
            problem("the chunk was not read: %s" % refusal, {"chunk_offset": chunk_offset})
            continue
        try:
            chunk = ChunkHeader(raw, 0)
        except Exception as exc:
            report["chunks_not_read"] += 1
            problem("the chunk is not readable: %s" % exc, {"chunk_offset": chunk_offset})
            continue
        report["chunks_read"] += 1
        for kind, offset, xml, message in read_chunk(chunk):
            check_stop()
            where = {"chunk_offset": chunk_offset, "record_offset": chunk_offset + offset if offset is not None else None}
            if kind == "timeout":
                c["parse_errors"] += 1
                problem("the chunk took more than %d seconds to read; the records after this point in it were not read" % CHUNK_SECONDS, where)
            elif kind == "chain":
                c["parse_errors"] += 1
                problem("the record chain of this chunk broke: %s" % message, where)
            elif kind == "record_error":
                c["parse_errors"] += 1
                problem("a record could not be rendered: %s" % message, where)
            else:
                try:
                    ev = event_from_xml(xml)
                except Exception as exc:
                    c["examined"] += 1
                    c["parse_errors"] += 1
                    problem("a record's XML could not be read: %s" % exc, where)
                    continue
                blocks.add(ev, where, problem)
    trailing = (file_bytes - header_bytes) - slots * CHUNK_SIZE if file_bytes > header_bytes else 0
    if trailing:
        fh.seek(header_bytes + slots * CHUNK_SIZE)
        if fh.read(len(CHUNK_MAGIC)) == CHUNK_MAGIC:
            problem("the file ends %d bytes into a chunk (a chunk is %d): the records in that part are not read here" % (trailing, CHUNK_SIZE), {})
    return report


def read_jsonl(fh, blocks, problem, over):
    """The rows of evtx_query, one per line, each read to a bound of MAX_LINE bytes."""
    c = blocks.c
    line_no = 0
    stopped = False
    while True:
        check_stop()
        if out_of_time() or over():
            stopped = True
            problem("the clock of the run ran out after line %d: the lines after it were not read" % line_no, {"line": line_no})
            break
        line = fh.readline(MAX_LINE + 1)
        if not line:
            break
        line_no += 1
        if len(line) > MAX_LINE and not line.endswith(b"\n"):
            c["lines_too_long"] += 1
            problem("a line is longer than %d bytes and was not read" % MAX_LINE, {"line": line_no})
            while True:
                rest = fh.readline(1 << 20)
                if not rest or rest.endswith(b"\n"):
                    break
            continue
        if not line.strip():
            continue
        try:
            row = json.loads(line)
            if isinstance(row, dict) and "parse_error" in row:
                c["parse_errors"] += 1
                problem("evtx_query could not read this record and wrote an error row: the record is not in this input", {"line": line_no})
                continue
            ev = event_from_row(row)
        except Exception as exc:
            c["examined"] += 1
            c["parse_errors"] += 1
            problem("the line is not a row of evtx_query: %s" % type(exc).__name__, {"line": line_no})
            continue
        off = row.get("record_offset")
        chunk = row.get("chunk_offset")
        where = {"record_offset": off if isinstance(off, int) and not isinstance(off, bool) else None,
                 "chunk_offset": chunk if isinstance(chunk, int) and not isinstance(chunk, bool) else None, "line": line_no}
        blocks.add(ev, where, problem)
    return {"lines_read": line_no, "stopped_by_time": stopped}


def main():
    set_deadline(DEADLINE_SECONDS)
    seal_stop_after(56.5)                 # the manifest allows 60, less 3.5: no seal runs on past that (the rest is withheld whole)
    install_signal_handlers()
    try:
        args = json.load(sys.stdin)
    except ValueError as exc:
        fail("arguments are not valid JSON", reason=str(exc))
    if not isinstance(args, dict):
        fail("the arguments must be a JSON object")
    path = args.get("path")
    if not isinstance(path, str) or not path:
        fail("path is required: an .evtx file, or a JSON Lines file of evtx_query rows")
    input_format = args.get("input_format", "auto")
    if input_format not in ("auto", "evtx", "jsonl"):
        fail("input_format must be auto, evtx or jsonl")
    limit = whole(args, "limit", 100, 1)
    write_text = flag(args, "write_text")
    write_values = flag(args, "write_values")
    if write_text and text_refused():
        fail("write_text is refused: the reassembled text of script blocks is written only in a job the harness runs as secret output "
             "(job_run with secret_output: true), where the file is a sealed secret output. Nothing was written.", write_text=True)
    try:
        bind_values(write_values, "powershell_blocks")
    except ValuesRefused as exc:
        fail(str(exc))
    OWN_NAMES.add(path)
    fh = open_regular(path)
    try:
        file_bytes = os.fstat(fh.fileno()).st_size
        magic = fh.read(len(FILE_MAGIC))
        fh.seek(0)
        if input_format == "evtx" and magic != FILE_MAGIC:
            fail("not an EVTX file: it does not begin with ElfFile", path=path)
        kind = input_format if input_format != "auto" else ("evtx" if magic == FILE_MAGIC else "jsonl")
        if kind == "evtx":
            try:
                import Evtx.Evtx  # noqa: F401
            except ImportError as exc:
                fail("python-evtx is not installed", hint="python3 -m pip install python-evtx", reason=str(exc))

        # The names of the whole results are made from what was asked about and never from the text: no name holds a digest of a block.
        key = [path, kind, bool(write_text)]
        blocks_page = CompletePage("powershell_blocks", key, limit)
        fragments_page = CompletePage("powershell_blocks-fragments", key, 1)
        problems_page = SealedPage("powershell_blocks-problems", key, 40)
        text_holder = NoReplacePage("powershell_blocks-text", key, 1) if write_text else None
        spool = spool_path = None
        if write_text:
            try:
                text_holder.path.parent.mkdir(parents=True, exist_ok=True)
                fd, name = tempfile.mkstemp(dir=text_holder.path.parent, prefix=".powershell_blocks-spool-")
                TEMPS.append(name)
                spool_path = name
                spool = os.fdopen(fd, "wb")
            except OSError as exc:
                fail("the text file cannot be made: %s. Outside a job the place is your own work/<your id>/ directory; in a job it is $OUT." % (exc.strerror or exc))
        blocks = Blocks(spool)

        def problem(why, where):
            blocks.c["problems"] += 1
            if blocks.c["problems"] <= MAX_PROBLEM_ROWS:
                problems_page.add({"why": why, **{k: v for k, v in where.items() if v is not None}})

        def over():
            return time.monotonic() - STARTED > READ_SECONDS

        try:
            report = read_evtx(fh, file_bytes, blocks, problem, over) if kind == "evtx" else read_jsonl(fh, blocks, problem, over)
        except ResultWriteError as exc:
            fail("the spool of the text could not be written: %s. Outside a job the place is your own work/<your id>/ directory; in a job it is $OUT." % exc,
                 records_examined=blocks.c["examined"])
        finally:
            if spool is not None:
                try:
                    spool.close()
                except OSError:
                    pass
    finally:
        fh.close()

    c = blocks.c
    keys = sorted(blocks.groups)
    by_status = {"complete": 0, "gaps": 0, "conflict": 0}
    equal_extra = 0
    by_source = {}
    text_out = text_tmp = text_src = None
    text_done = text_skipped = 0
    not_listed = 0
    if write_text:
        try:
            fd, name = tempfile.mkstemp(dir=text_holder.path.parent, prefix=".powershell_blocks-text-")
            TEMPS.append(name)
            text_tmp = name
            os.chmod(name, 0o600)
            text_out = os.fdopen(fd, "wb")
            text_src = open(spool_path, "rb")
        except OSError as exc:
            fail("the text file cannot be made: %s" % (exc.strerror or exc))
    for i, (source, computer, sbid) in enumerate(keys):
        if STOP["signal"] is not None:
            raise Interrupted(STOP["signal"])
        if time.monotonic() - STARTED > OUTPUT_SECONDS:
            not_listed = len(keys) - i          # the rows of these blocks are not made: the clock for the files is spent
            text_skipped += not_listed if write_text else 0
            break
        group = blocks.groups[(source, computer, sbid)]
        a = analyse(group["frags"])
        by_status[a["status"]] += 1
        equal_extra += sum(d[1] - 1 for d in a["dups"] if d[2]) if a["status"] == "complete" else 0
        by_source[source] = by_source.get(source, 0) + 1
        withheld = sum(1 for f in a["order"] if f[11] & 2)
        row = {
            "block": i, "source": source, "channel": sorted(group["channels"])[0] if group["channels"] else "", "channels": sorted(group["channels"]), "computer": computer, "script_block_id": sbid,
            "block_status": a["status"], "expected_fragments": a["expected"], "message_totals": a["totals"][:LISTED], "fragment_count": len(a["order"]),
            "numbers_distinct": a["distinct"], "missing_count": a["missing_count"], "missing_ranges": a["missing"][:LISTED], "missing_ranges_total": len(a["missing"]),
            "duplicate_numbers": len(a["dups"]), "unequal_copies": a["unequal"],
            "duplicates": [{"message_number": d[0], "records": d[1], "same_text": d[2]} for d in a["dups"][:LISTED]],
            "numbers_out_of_range": a["out_of_range"], "levels": a["levels"], "auto_logged_warning": 3 in a["levels"], "paths": group["paths"],
            "paths_not_listed": group["path_extra"], "text_length": sum(f[6] for f in a["firsts"]), "text_bytes": sum(f[10] for f in a["firsts"]),
            "text_withheld_upstream": withheld,
            "records": [[f[3], f[4]] for f in a["order"]] if len(a["order"]) <= INLINE_RECORDS else None,
        }
        blocks_page.add(row)
        first_by_number = {f[0]: f for f in a["firsts"]}
        for f in a["order"]:
            first = first_by_number[f[0]]
            frag = {"block": i, "message_number": f[0], "message_total": f[1], "arrival": f[2], "record_id": f[3], "record_offset": f[4], "chunk_offset": f[5],
                    "text_length": f[6], "level": f[8],
                    "same_text_as_first": None if f is first else (f[6] == first[6] and f[7] == first[7])}
            fragments_page.add(frag)
        if text_out is not None:
            if out_of_time():
                text_skipped += 1
                continue
            try:
                head = json.dumps({"block": i, "source": source, "channel": row["channel"], "computer": computer, "script_block_id": sbid,
                                   "block_status": a["status"], "numbers_joined": len(a["firsts"])}, ensure_ascii=True)[:-1] + ', "text": "'
                text_out.write(head.encode("ascii"))
                for f in a["firsts"]:
                    text_src.seek(f[9])
                    piece = text_src.read(f[10]).decode("utf-8", "surrogatepass")
                    text_out.write(json.dumps(piece, ensure_ascii=True)[1:-1].encode("ascii"))
                text_out.write(b'"}\n')
            except OSError as exc:
                fail("the text file could not be written: %s. Outside a job the place is your own work/<your id>/ directory; in a job it is $OUT." % (exc.strerror or exc))
            text_done += 1
    if text_src is not None:
        text_src.close()
    text_shown = None
    if text_out is not None:
        try:
            text_out.flush()
            os.fsync(text_out.fileno())
            text_out.close()
            made = place_without_replacing(Path(text_tmp), text_holder.path)
        except OSError as exc:
            fail("the text file could not be placed: %s" % (exc.strerror or exc))
        TEMPS.remove(text_tmp)
        text_shown = text_holder.shown[: len(text_holder.shown) - len(text_holder.path.name)] + made.name
        OWN_NAMES.add(text_shown)
        try:
            os.unlink(spool_path)
            TEMPS.remove(spool_path)
        except (OSError, ValueError):
            pass
    blocks_result = blocks_page.finish()
    fragments_result = fragments_page.finish()
    problems_result = problems_page.finish()

    reasons = []
    if report.get("stopped_by_time"):
        reasons.append("the clock of the run ran out before the whole input was read")
    if c["parse_errors"]:
        reasons.append("%d record(s) or line(s) could not be read (parse_errors)" % c["parse_errors"])
    if report.get("chunks_not_read"):
        reasons.append("%d chunk(s) were not read" % report["chunks_not_read"])
    if c["malformed"]:
        reasons.append("%d 4104 record(s) were not grouped (fragments_malformed)" % c["malformed"])
    if c["not_kept_fragments"]:
        reasons.append("%d fragment(s) were not kept: the run keeps at most %d fragments in %d blocks" % (c["not_kept_fragments"], MAX_FRAGMENTS, MAX_BLOCKS))
    if c["lines_too_long"]:
        reasons.append("%d line(s) were longer than %d bytes and were not read" % (c["lines_too_long"], MAX_LINE))
    if c["withheld_upstream"]:
        reasons.append("%d fragment(s) hold text evtx_query withheld, so their blocks are not the evidence's text" % c["withheld_upstream"])
    if c["paths_not_listed"]:
        reasons.append("%d Path value(s) are not listed" % c["paths_not_listed"])
    if text_skipped:
        reasons.append("%d block(s) were not written to the text file: the clock ran out" % text_skipped)
    if not_listed:
        reasons.append("%d of %d block(s) were not listed: the output clock (%d seconds) ran out, so their rows and fragments are in no file (blocks_not_listed)" % (not_listed, len(keys), OUTPUT_SECONDS))
    if by_status["gaps"]:
        reasons.append("%d block(s) have fragments missing (block_status gaps)" % by_status["gaps"])
    if by_status["conflict"]:
        reasons.append("%d block(s) have fragments that disagree (block_status conflict)" % by_status["conflict"])
    if c["problems"]:
        reasons.append("%d problem(s) are named under problems" % c["problems"])
    if reasons:
        status, basis = "partial", "; ".join(reasons)
    else:
        status = "complete"
        basis = "every record of the input was read and every block has every number from 1 to its one MessageTotal"
        if equal_extra:
            basis += "; %d extra copy(ies) of equal text are listed under duplicates" % equal_extra
    answer = {
        "parser": PARSER,
        "status": status,
        "status_basis": basis,
        "path": path,
        "input_format": kind,
        "file_bytes": file_bytes,
        **report,
        "records_examined": c["examined"],
        "records_4104": c["records_4104"],
        "records_other_events": c["other_events"],
        "parse_errors": c["parse_errors"],
        "fragments_kept": blocks.kept,
        "fragments_not_kept": c["not_kept_fragments"],
        "blocks_not_kept": c["not_kept_blocks"],
        "fragments_malformed": c["malformed"],
        "fragments_text_withheld_upstream": c["withheld_upstream"],
        "fragments_with_unpaired_surrogates": c["surrogates"],
        "lines_too_long": c["lines_too_long"],
        "block_count": len(keys),
        "blocks_listed": blocks_result["matched"],
        "blocks_not_listed": not_listed,
        "blocks_by_status": by_status,
        "blocks_by_source": by_source,
        "returned": blocks_result["returned"],
        "truncated": blocks_result["truncated"],
        "blocks": blocks_page.page,
        "problem_count": c["problems"],
        "problems": problems_page.page,
        "note": "A block is the 4104 records that share a source (Windows PowerShell or PowerShell 7, kept apart), a Computer and a ScriptBlockId, in the order of "
                "MessageNumber. block_status: complete (every number 1..MessageTotal present, one MessageTotal; extra copies of equal text are listed under duplicates), gaps (numbers missing, listed as ranges), conflict "
                "(MessageTotal values that disagree, a number outside 1..MessageTotal, or copies of one number with different text). A missing fragment is a fact "
                "about the log (it wrapped, was cleared or was carved), not about the script. Level 3 (a Warning) is a block PowerShell logged by itself. The text of "
                "the blocks is never shown and never evaluated or decoded; text_length counts the characters of the first copy of every number. Per fragment, "
                "fragments_file holds the EventRecordID and the record's byte offset.",
    }
    if blocks_result.get("all_results"):
        answer["blocks_file"] = blocks_result["all_results"]
    if fragments_result.get("all_results"):
        answer["fragments_file"] = fragments_result["all_results"]
    if problems_result.get("all_results"):
        answer["all_problems"] = problems_result["all_results"]
    if write_text:
        answer["text_file"] = text_shown
        answer["text_written"] = text_done
        answer["text_blocks_not_written"] = text_skipped
    OWN_NAMES.add(answer["status_basis"])                    # made of counts and the tool's own words
    cleanup()
    emit(answer, indent=2)
    close_values()


def _code(stop):
    return stop.code if isinstance(stop.code, int) else (0 if stop.code is None else 1)


def _leave(code):
    """End the call at once, after the answer is out. The interpreter's own teardown resets the signal handlers to their defaults before it frees
    what the call held, and a stop signal that lands there kills the process by its default action (exit null, not 128 + the signal) with a whole
    answer already printed. What the interpreter would have run at its end (the atexit hooks that remove a temporary file) is run here, with the
    handlers still in; a signal before this point is answered by the handlers as before."""
    try:
        sys.stdout.flush()
    except SystemExit as stop:
        code = _code(stop)
    except Exception:  # noqa: BLE001 - a reader that is gone: the exit code is the one the call had
        pass
    try:
        sys.stderr.flush()
    except Exception:  # noqa: BLE001
        pass
    try:
        import atexit as _atexit
        _atexit._run_exitfuncs()
    except Exception:  # noqa: BLE001 - a hook that fails is not a failure of the answer
        pass
    os._exit(code)


if __name__ == "__main__":
    exit_code = 0
    try:
        try:
            main()
        except SystemExit:
            cleanup()
            raise
        except Interrupted as stop:
            cleanup()
            emit({"error": "stopped by signal %d" % stop.signum, "status": "failed", "interrupted": True, "status_basis": "the tool was stopped by signal %d; nothing it had read is an answer, and no file of this run is left" % stop.signum, "signal": stop.signum})
            sys.exit(128 + stop.signum)
        except Exception as exc:                                  # whatever hostile input does, the answer is JSON
            cleanup()
            emit({"error": "the read failed", "status": "failed", "status_basis": "the tool stopped with an unexpected error", "reason": "%s: %s" % (type(exc).__name__, exc)})
            sys.exit(1)
    except SystemExit as stop:
        exit_code = _code(stop)
    _leave(exit_code)
