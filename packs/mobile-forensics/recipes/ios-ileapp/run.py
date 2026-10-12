#!/usr/bin/env python3
"""A broad extraction of an iOS full file-system acquisition with iLEAPP.

The ios-filesystem recipe only inventories the tar: it reads headers and
parses no artefact content. This one hands the whole acquisition (a tar,
plain or compressed, or a zip) to iLEAPP, which runs its artefact modules
over it and writes a report per artefact: TSV files, a timeline database and
an HTML report. The TSVs and databases are the searchable form; they are
listed in index.tsv, and every file iLEAPP wrote is kept under ileapp/.

    run.py detect --target T [--probe-out DIR]   exit 0 applies, 1 does not
    run.py run --target T --out DIR

WHAT `complete` MEANS. iLEAPP exiting 0 with a TSV in its output says the
program ran and wrote something; it does not say that every module ran, and a
module that failed while others wrote their reports leaves the same trace. So
the run reads iLEAPP's own log (the stdout and stderr it keeps whole, read as one
account) for one outcome per module, and writes them to modules.tsv (the text of
a log line is not copied into any of the run's files except as the kept log itself):

    completed      started, completed, and does not say it found nothing
    no_record      started, completed, and said "No file found" or "No data
                   found" and reported no record: it is never read as "the
                   artefact is absent from the phone", only as what that module
                   found in this acquisition
    unsupported    started, completed, reported no record and said "Unsupported
                   version for ..." (the module's own gate on the operating-system
                   version): the module did not read this acquisition's version,
                   which says nothing about whether the artefact is there
    errored        the log says the module failed ("artifact failed after", or
                   "Reading <artefact> artifact had errors!")
    errors_logged  completed, and wrote lines that speak of an error (a module
                   that cannot read a table says so and completes)
    unknown        started, and the log does not say how it ended

The status is `complete` only when the program exited 0, wrote at least one TSV
report (a file under a data/ or media/ folder of the report is a copy of a file the
program read, not a report), the log was recognised (at least one module started),
every module is completed, no_record or unsupported, no line outside a module
speaks of an error, stderr holds no line that is not a log line of the shapes
above, the log says how many modules it
will parse (an "Artifact to parse: N" line, or the [i/N] prefix of a module line)
and that many started, and the log ends with "Processes completed.". The log shape is that of a real iLEAPP v2026.4.1 run; a release that logs
differently leaves every module unknown and the run partial, and the receipt says so.

A run that is stopped before its end leaves coverage.json saying partial, so
what it wrote is read as partial and never as complete. A run never writes over
an earlier run's output: if the output directory already holds ileapp/ or a
coverage.json, it refuses and leaves them as they are. The exit status is the
program's own (0 when it exited 0, 1 otherwise); the answer is the `status` in
coverage.json, and `ok` in the printed line says only that the program exited 0.

The input is a tar (plain, gzip, bzip2 or xz) or a zip, told apart by what the file
is and not by what zipfile finds in it: a tar header whose checksum holds, or a
compressed stream, is a tar even when its last member is a zip. A tar is scanned for
the platform's marker header by header, apart from the library that lists it: an
extended header (a GNU long name, a pax header) that declares more than 16 MiB is
not read, since the library would hold it whole in memory.
"""
import argparse
import io
import json
import os
import re
import shutil
import struct
import subprocess
import sys
import tarfile
import zipfile
import zlib

IOS_MARKERS = (
    "private/var/mobile/",
    "private/var/containers/",
    "system/library/coreservices/systemversion.plist",
)
NOT_COVERED = ("artefacts no module of the pinned iLEAPP release parses; deleted records beyond what a module reads "
               "itself (no carving); protected data that needs a key it does not have; archives nested inside the acquisition; "
               "a module the log does not account for as completed")

# --- the module receipt: held equal to the one in the Android recipe by a test ----------------------------
# The log lines a LEAPP program prints for each artefact module, as iLEAPP v2026.4.1 prints them:
#   [12/1139] name [module] artifact started at 09:29:44 UTC
#   Found 3 records for X | No file found | No data found for X     (what the module says it did)
#   Unsupported version for X for iOS 16.3                          (a module's own gate on the OS version)
#   name [module] artifact completed in 0.0s   |   name [module] artifact failed after 0.0s
#   Reading name artifact had errors!          (before a failure, with the module's own error text)
#   Artifact to parse: 1139   ...   Processes completed.
# A count in "Found" has thousands separators ("Found 205,098 records for X"). A release that prints other lines
# leaves its modules unknown, and the run partial.
LOG_START = re.compile(r"^(?:\[\d+/(?P<total>\d+)\] )?(?P<name>.+?) \[(?P<module>[^\[\]]+)\] artifact started(?: at .+)?\s*$")
LOG_DONE = re.compile(r"^(?P<name>.+?) \[(?P<module>[^\[\]]+)\] artifact completed(?: in .+)?\s*$")
LOG_FAILED = re.compile(r"^(?P<name>.+?) \[(?P<module>[^\[\]]+)\] artifact failed(?: after .+)?\s*$")
LOG_ERROR = re.compile(r"^Reading (?P<name>.+?) artifact had errors!\s*$")
LOG_FOUND = re.compile(r"^Found (?P<n>\d{1,3}(?:,\d{3})+|\d+) records? for ")
LOG_NO_FILE = re.compile(r"^No files? found\s*$")
LOG_NO_DATA = re.compile(r"^No data found for ")
LOG_UNSUPPORTED = re.compile(r"^Unsupported version for .+ for \S+ \S+\s*$")
LOG_EXPECTED = re.compile(r"^Artifact to parse: (?P<n>\d+)\s*$")
# Words a module uses when it could not do what it set out to do and went on. A line that holds one, inside a
# module that then completed, makes the module errors_logged, and one outside any module is counted on its own:
# a missed word makes a run complete that is not, a needless one makes it partial, and the second costs a look
# at the log.
LOG_PROBLEM = re.compile(r"\b(\w*(errors?|exceptions?)|traceback|unable|failed|failures?|could not|couldn't|cannot|can't|corrupt(ed)?|"
                         r"malformed|invalid|permission denied|no such (table|column|file)|not a database|unsupported|skipping|skipped|"
                         r"errno|no space left|out of memory|killed|segmentation fault|core dumped|aborted)\b", re.I)
LOG_LINE_BOUND = 4000
FIRST_UNATTRIBUTED = 20
STATUSES = ("completed", "no_record", "unsupported", "errored", "errors_logged", "unknown")


def tsv_escape(value):
    """One line, one field, nothing hidden: backslash, tab, newline, return and other controls escaped."""
    out = []
    for ch in str(value):
        o = ord(ch)
        if 0xDC80 <= o <= 0xDCFF:
            out.append("\\x%02x" % (o - 0xDC00))
        elif ch == "\\":
            out.append("\\\\")
        elif ch == "\t":
            out.append("\\t")
        elif ch == "\n":
            out.append("\\n")
        elif ch == "\r":
            out.append("\\r")
        elif o < 0x20 or o == 0x7F:
            out.append("\\x%02x" % o)
        else:
            out.append(ch)
    return "".join(out)


def read_log(path, source, events, facts):
    """Append (kind, artefact, module, source, line number, extra) for each module line of a kept log, and
    note what the log says about the run itself; count tracebacks and the lines that are not empty and that no
    pattern here recognises (on stderr, each is a line nothing explains). A line is read to LOG_LINE_BOUND
    bytes and the rest of it skipped. The text of a log line is never kept."""
    tracebacks = unread = 0
    try:
        with open(path, "rb") as fh:
            number = 0
            while True:
                raw = fh.readline(LOG_LINE_BOUND + 1)
                if not raw:
                    break
                number += 1
                if len(raw) > LOG_LINE_BOUND and not raw.endswith(b"\n"):
                    while True:
                        rest = fh.readline(1 << 16)
                        if not rest or rest.endswith(b"\n"):
                            break
                line = raw[:LOG_LINE_BOUND].decode("utf-8", "replace").rstrip("\r\n")
                found = LOG_START.match(line)
                if found:
                    events.append(("start", found.group("name"), found.group("module"), source, number, None))
                    if found.group("total"):
                        facts["total"] = int(found.group("total"))
                    continue
                found = LOG_DONE.match(line)
                if found:
                    events.append(("done", found.group("name"), found.group("module"), source, number, None))
                    continue
                found = LOG_FAILED.match(line)
                if found:
                    events.append(("failed", found.group("name"), found.group("module"), source, number, None))
                    continue
                found = LOG_ERROR.match(line)
                if found:
                    events.append(("error", found.group("name"), None, source, number, None))
                    continue
                found = LOG_FOUND.match(line)
                if found:
                    events.append(("found", None, None, source, number, int(found.group("n").replace(",", ""))))
                    continue
                if LOG_NO_FILE.match(line):
                    events.append(("nofile", None, None, source, number, None))
                    continue
                if LOG_NO_DATA.match(line):
                    events.append(("nodata", None, None, source, number, None))
                    continue
                if LOG_UNSUPPORTED.match(line):
                    events.append(("unsupported", None, None, source, number, None))
                    continue
                found = LOG_EXPECTED.match(line)
                if found:
                    facts["expected"] = int(found.group("n"))
                    continue
                if line.startswith("Processes completed."):
                    facts["end"] = True
                    continue
                if line.strip():
                    unread += 1
                if line.startswith("Traceback (most recent call last):"):
                    tracebacks += 1
                if LOG_PROBLEM.search(line):
                    events.append(("problem", None, None, source, number, None))
    except OSError:
        pass
    return tracebacks, unread


def receipt(events):
    """One row per module the log names, in the order they started, and what could not be attributed.

    A module's lines are those between its start and its completed or failed line. errored: the log says
    it failed. errors_logged: it completed, and wrote lines that speak of an error (a module that could
    not read a table says so and completes). unsupported: it completed, reported no record and said its
    version gate does not take this acquisition's operating system. no_record: it completed and said it
    found no file, or no data. completed: it completed and does not say it found nothing. unknown: it
    started and the log does not say how it ended. A line that speaks of an error outside any module
    (between modules, before the first, after the last) is returned on its own, as a locator.
    """
    order, modules, current, unattributed, outside = [], {}, None, [], []
    for kind, name, module, source, line, extra in events:
        if kind == "start":
            key = (module, name)
            if key not in modules:
                modules[key] = {"artefact": name, "module": module, "state": "started", "log": source, "line": line,
                                "records": 0, "nofile": False, "nodata": False, "gated": False, "notes": 0, "errored": False}
                order.append(key)
            elif modules[key]["state"] in ("done", "failed"):
                modules[key]["state"] = "started"        # started again: an error already seen stays
            current = key
        elif kind in ("done", "failed"):
            row = modules.get((module, name))
            if row is None:
                unattributed.append({"what": "a %s line with no start" % ("completed" if kind == "done" else "failed"), "artefact": name, "log": source, "line": line})
                continue
            row["state"] = "done" if kind == "done" else "failed"
            if kind == "failed":
                row["errored"] = True
            current = None
        elif kind == "error":
            key = current if current is not None and modules[current]["artefact"] == name else None
            if key is None:
                for candidate in reversed(order):
                    if modules[candidate]["artefact"] == name:
                        key = candidate
                        break
            if key is None:
                unattributed.append({"what": "an error line for an artefact that never started", "artefact": name, "log": source, "line": line})
            else:
                modules[key]["errored"] = True
                modules[key]["error_log"], modules[key]["error_line"] = source, line
        elif current is not None:
            row = modules[current]
            if kind == "found":
                row["records"] += extra
            elif kind == "nofile":
                row["nofile"] = True
            elif kind == "nodata":
                row["nodata"] = True
            elif kind == "unsupported":
                row["gated"] = True
            elif kind == "problem":
                row["notes"] += 1
        elif kind == "problem":
            outside.append({"log": source, "line": line})
    rows = []
    for key in order:
        row = modules[key]
        if row["errored"]:
            status = "errored"
        elif row["state"] != "done":
            status = "unknown"
        elif row["notes"]:
            status = "errors_logged"
        elif row["records"] == 0 and row["gated"]:
            status = "unsupported"
        elif row["records"] == 0 and (row["nofile"] or row["nodata"]):
            status = "no_record"
        else:
            status = "completed"
        reason = {"no_record": "no source file" if row["nofile"] else "no data", "unsupported": "the module does not take this operating-system version"}.get(status)
        rows.append({**row, "status": status, "reason": reason})
    counts = {name: 0 for name in STATUSES}
    for row in rows:
        counts[row["status"]] += 1
    return rows, counts, unattributed, outside


def write_modules(out, rows):
    with open(os.path.join(out, "modules.tsv"), "w", encoding="utf-8", newline="\n") as handle:
        handle.write("n\tstatus\tartefact\tmodule\trecords\tlogged_error_lines\tlog\tline\n")
        for n, row in enumerate(rows):
            handle.write("%d\t%s\t%s\t%s\t%d\t%d\t%s\t%d\n" % (n, row["status"], tsv_escape(row["artefact"]), tsv_escape(row["module"]),
                                                              row["records"], row["notes"], row["log"], row["line"]))
# --- end of the module receipt -------------------------------------------------------------------------


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
# not: whether the end-of-archive block came, whether a header would be refused (a checksum that does not
# match, a number that does not parse), how many members there are, and whether an extended header declares
# more than the library should be allowed to hold in memory (it reads a GNU long name or a pax header whole).
EXTENDED_HEADER_LIMIT = 16 << 20
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
        self.end_at = None           # where the end-of-archive block starts
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

    def finish_pax(self):
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
        if block == b"\0" * 512:
            self.ended, self.end_at = True, start
            return
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
            self.skip = -(-size // 512) * 512
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

    `cut_short`: the bytes were stopped by a budget, so neither the end block nor the count is judged.
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
        errors.append("the tar ends without its end-of-archive block (%d bytes read): the archive is cut short or damaged, and the listing is what came before the cut" % watch.position)
    if not cut_short and listed != watch.members:
        errors.append("the tar reader listed %d members and a header-by-header walk counted %d: the two disagree, so the listing may be missing members" % (listed, watch.members))
    return tar_end, limits, errors
# --- tar watch: end ------------------------------------------------------------------------------


# --- tar listing: begin --------------------------------------------------------------------------
# Held byte for byte equal in the three recipes that open a tar by its path (a test compares the copies).
# A plain tar is read through Guarded and a gzip, bzip2 or xz one through Decoded; both keep the watch
# just ahead of the library and give it an end of data where the watch stops it.
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


class Decoded(io.RawIOBase):
    """A gzip, bzip2 or xz stream as a plain file for the tar library, read in pieces and followed by the watch; nothing
    is served from the point where the watch stops it."""

    PIECE = 1 << 20

    def __init__(self, source, kind, watch):
        self.source, self.kind, self.watch = source, kind, watch
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

    def __init__(self, path):
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
                self.source = Decoded(self.handle, kind, self.watch)
                mode = "r|"
                self.source = io.BufferedReader(self.source)
            self.archive = tarfile.open(fileobj=self.source, mode=mode, encoding="utf-8", errors="surrogateescape")
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


def ios_name(name):
    low = name.lower()
    return any(marker in low for marker in IOS_MARKERS)


def container_kind(path):
    """tar or zip, decided by what the file is: a tar header whose checksum holds, or a gzip, bzip2 or xz stream (a
    compressed tar), is a tar; a file that starts with a zip signature is a zip; a file that is neither is still a zip
    when zipfile finds an end record in it (data before the first header, as in a self-extracting archive). The tar test
    comes first because zipfile finds the end record of a zip that is a MEMBER of a tar, near the tar's end, and would
    take the whole tar for a zip. Not zipfile.is_zipfile alone, whose answer changed between Python 3.11 and 3.14 for an
    archive whose end-of-central-directory record is damaged: dispatch does not depend on a library's verdict."""
    with open(path, "rb") as fh:
        head = fh.read(512)
    if len(head) == 512 and any(head) and tar_header(head) is not None:
        return "tar"
    if compression_of(head) is not None:
        return "tar"
    if head[:4] in (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08"):
        return "zip"
    try:
        with zipfile.ZipFile(path):
            return "zip"
    except (zipfile.BadZipFile, OSError):
        return "tar"


def detect(path):
    """(applies, why, kind): kind is iLEAPP's input type, tar or zip."""
    if not os.path.isfile(path):
        return False, "not a readable file", None
    try:
        kind = container_kind(path)
    except OSError as exc:
        return False, "not a readable file: %s" % (exc.strerror or exc), None
    if kind == "zip":
        try:
            with zipfile.ZipFile(path) as archive:
                for name in archive.namelist():
                    if ios_name(name):
                        return True, "zip members have an iOS full file-system root", "zip"
        except (zipfile.BadZipFile, OSError) as exc:
            return False, "not a readable zip: %s" % exc, None
        return False, "zip has no iOS full file-system marker", None
    try:
        with TarList(path) as listing:
            for member in listing.archive:
                if ios_name(member.name):
                    return True, "tar members have an iOS full file-system root", "tar"
                listing.archive.members = []
            if listing.watch.violation is not None:
                return False, "tar has no iOS full file-system marker before a header the scan does not read (an extended header of %d bytes at offset %d)" % (listing.watch.violation, listing.watch.violation_at), None
    except (tarfile.TarError, OSError, EOFError) as exc:
        return False, "not a readable tar or zip: %s" % exc, None
    return False, "tar has no iOS full file-system marker", None


def write_coverage(out, status, covered, errors, limits=(), **more):
    with open(os.path.join(out, "coverage.json"), "w", encoding="utf-8") as handle:
        json.dump({"recipe": "ios-ileapp", "status": status, "covered": covered, "not_covered": NOT_COVERED,
                   "limits_hit": list(limits), "errors": list(errors), **more}, handle, indent=2, sort_keys=True)
        handle.write("\n")


def program():
    for name in ("ileapp", "ileapp.py"):
        found = shutil.which(name)
        if found:
            return os.path.abspath(found)
    return None


def index(out, report):
    """Every TSV and database iLEAPP wrote, one row each, relative to out/. A file under a data/ or media/ folder is a
    copy of a file of the acquisition that the program read, and is labelled so: it is not a report."""
    rows = []
    for dirpath, dirs, files in os.walk(report):
        dirs.sort()
        for name in sorted(files):
            low = name.lower()
            rel = os.path.relpath(os.path.join(dirpath, name), out)
            copied = any(part in ("data", "media") for part in rel.split(os.sep)[:-1])
            if not low.endswith((".tsv", ".db", ".sqlite", ".kml")):
                continue
            if copied:
                rows.append((rel, "copy of a file of the acquisition that iLEAPP read (%s), not a report" % name, True))
            elif low.endswith(".tsv"):
                rows.append((rel, "iLEAPP artefact report %s (TSV, one row per record)" % name[:-4], False))
            elif low.endswith((".db", ".sqlite")):
                rows.append((rel, "iLEAPP database %s (SQLite: the timeline, or every artefact's rows)" % name, False))
            else:
                rows.append((rel, "iLEAPP locations %s (KML)" % name, False))
    return rows


def write_index(out, rows):
    with open(os.path.join(out, "index.tsv"), "w", encoding="utf-8", newline="\n") as handle:
        for rel, what, _copied in rows:
            handle.write("%s\t%s\n" % (rel.replace("\t", " "), what))
        handle.write("modules.tsv\tone row per module the iLEAPP log names: completed, no_record, unsupported, errored, errors_logged or unknown, with the records it reports and the log line\n")
        handle.write("ileapp.stdout\tiLEAPP's standard output, whole: the log that modules.tsv points into\n")
        handle.write("ileapp.stderr\tiLEAPP's standard error, whole\n")


def child_files(directory):
    """How many files and links a program left in a directory this recipe gave it: kept, never deleted."""
    count = 0
    for _dirpath, dirs, files in os.walk(directory):
        count += len(files) + sum(1 for d in dirs if os.path.islink(os.path.join(_dirpath, d)))
    return count


def run(path, kind, out):
    out = os.path.abspath(out)       # the program runs from a directory under out: nothing here may be relative
    report = os.path.join(out, "ileapp")
    if os.path.lexists(report) or os.path.lexists(os.path.join(out, "coverage.json")):
        # Before anything is written: an earlier run's coverage and report stay as they are.
        print(json.dumps({"ok": False, "status": "refused", "why": "the output directory already holds ileapp/ or coverage.json: the recipe does not write over an earlier run"}))
        return 2
    os.makedirs(out, exist_ok=True)
    # Said before iLEAPP starts: a run stopped at its limit leaves this, and is read as partial.
    write_coverage(out, "partial", "started; iLEAPP did not finish (stopped before its end)", ["the run ended before iLEAPP did"])
    prog = program()
    if not prog:
        write_coverage(out, "failed", "nothing: iLEAPP is not in this image", ["ileapp is not on PATH in this job image"])
        return 1
    path = os.path.abspath(path)
    scratch = os.path.join(out, "ileapp-run")
    # The run directory is read-only in a job: the program's working directory and its temporary files
    # are under the output, and every file it leaves there is kept and counted.
    cwd = os.path.join(out, "ileapp-cwd")
    temp = os.path.join(out, "ileapp-tmp")
    for directory in (scratch, cwd, temp):
        os.makedirs(directory, exist_ok=True)
    env = dict(os.environ, TMPDIR=temp)
    with open(os.path.join(out, "ileapp.stdout"), "wb") as so, open(os.path.join(out, "ileapp.stderr"), "wb") as se:
        rc = subprocess.run([prog, "-t", kind, "-i", path, "-o", scratch], stdout=so, stderr=se, cwd=cwd, env=env).returncode
    made = [d for d in sorted(os.listdir(scratch)) if os.path.isdir(os.path.join(scratch, d)) and not os.path.islink(os.path.join(scratch, d))]
    layout, siblings = "whole output directory", False
    if len(made) == 1:
        os.rename(os.path.join(scratch, made[0]), report)
        left = sorted(os.listdir(scratch))
        if left:
            # Files the program wrote beside its report folder are kept, whole, in a directory of their own.
            os.rename(scratch, os.path.join(out, "ileapp-run-files"))
            siblings = True
            layout = "one report folder; %d file(s) beside it kept in ileapp-run-files/" % len(left)
        else:
            os.rmdir(scratch)
            layout = "one report folder"
    else:
        os.rename(scratch, report)
    kept = {}
    for name, directory in (("ileapp-cwd", cwd), ("ileapp-tmp", temp)):
        files = child_files(directory)
        if files:
            kept[name] = files
        else:
            for dirpath, _dirs, _files in os.walk(directory, topdown=False):
                try:
                    os.rmdir(dirpath)
                except OSError:
                    pass
    rows = index(out, report)
    reports = [row for row in rows if not row[2]]
    tsvs = sum(1 for rel, _what, _copied in reports if rel.lower().endswith(".tsv"))

    # Both streams are read into one account: a release that logs to stderr (Python's logging does by default)
    # has its module lines, its count and its end line read as well as one that logs to stdout.
    events, facts = [], {}
    read_log(os.path.join(out, "ileapp.stdout"), "ileapp.stdout", events, facts)
    tracebacks, stderr_lines = read_log(os.path.join(out, "ileapp.stderr"), "ileapp.stderr", events, facts)
    modules, counts, unattributed, outside = receipt(events)
    write_modules(out, modules)
    write_index(out, rows)
    recognised = bool(modules)
    expected = facts.get("expected", facts.get("total"))
    receipt_json = {"log_format_recognised": recognised, "counts": counts, "modules_listed_in": "modules.tsv",
                    "records_reported_by_modules": sum(m["records"] for m in modules),
                    "modules_the_log_says_it_will_parse": expected,
                    "log_says_processing_completed": bool(facts.get("end")),
                    "tracebacks_on_stderr": tracebacks, "unexplained_lines_on_stderr": stderr_lines,
                    "error_lines_outside_modules": len(outside), "first_error_lines_outside_modules": outside[:FIRST_UNATTRIBUTED],
                    "unattributed_log_lines": unattributed[:FIRST_UNATTRIBUTED],
                    "report_layout": layout, **({"files_beside_the_report": "ileapp-run-files/"} if siblings else {}),
                    **({"files_left_in_program_directories": kept} if kept else {})}
    errors = [] if rc == 0 else ["iLEAPP exited %d; its output is kept whole in ileapp.stdout and ileapp.stderr" % rc]
    problems = []
    named = lambda status: [m["artefact"] for m in modules if m["status"] == status][:5]
    if counts["errored"]:
        problems.append("%d module(s) errored: %s%s; see modules.tsv and ileapp.stdout" % (counts["errored"], ", ".join(named("errored")), " and others" if counts["errored"] > 5 else ""))
    if counts["errors_logged"]:
        problems.append("%d module(s) completed but logged error lines: %s%s; see modules.tsv and ileapp.stdout" % (counts["errors_logged"], ", ".join(named("errors_logged")), " and others" if counts["errors_logged"] > 5 else ""))
    if counts["unknown"]:
        problems.append("%d module(s) started and the log says nothing more about them" % counts["unknown"])
    if outside:
        where = ", ".join("%s line %d" % (o["log"], o["line"]) for o in outside[:5])
        problems.append("%d log line(s) outside any module speak of an error (%s%s)" % (len(outside), where, " and others" if len(outside) > 5 else ""))
    if stderr_lines:
        problems.append("%d line(s) on stderr that nothing explains%s; see ileapp.stderr" % (stderr_lines, " (%d of them tracebacks)" % tracebacks if tracebacks else ""))
    if unattributed:
        problems.append("%d log line(s) about a module that did not start" % len(unattributed))
    if recognised and expected is None:
        problems.append("the log does not say how many modules it will parse (no 'Artifact to parse' line, no [i/N] prefix): a module that never started cannot be told from one that was not asked for")
    elif recognised and len(modules) != expected:
        problems.append("the log says %d modules would be parsed and %d started" % (expected, len(modules)))
    if recognised and not facts.get("end"):
        problems.append("the log does not end with its processing-completed line")
    if rc == 0 and tsvs and not recognised:
        problems.append("the log has no module lines this recipe reads: per-module outcome is unknown for all of them")
    gated = counts["unsupported"]
    if rc == 0 and tsvs and not problems:
        write_coverage(out, "complete", "iLEAPP exited 0 over the %s and its log accounts for %d module(s): %d completed, %d with no record (no source file or no data)%s; %d TSV report(s)"
                       % (kind, len(modules), counts["completed"], counts["no_record"],
                          ", %d that do not take this operating-system version (see modules.tsv)" % gated if gated else "", tsvs), errors, modules=receipt_json)
    elif reports:
        write_coverage(out, "partial", "iLEAPP wrote %d report file(s); %d module(s) in its log: %d completed, %d no_record, %d unsupported, %d errored, %d errors_logged, %d unknown"
                       % (len(reports), len(modules), counts["completed"], counts["no_record"], gated, counts["errored"], counts["errors_logged"], counts["unknown"]),
                       (errors + problems) or ["iLEAPP wrote no TSV report"], modules=receipt_json)
    else:
        write_coverage(out, "failed", "nothing parsed", (errors + problems) or ["iLEAPP wrote no report"], modules=receipt_json)
    return 0 if rc == 0 else 1


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("detect", "run"))
    parser.add_argument("--target", required=True)
    parser.add_argument("--out")
    # The census asks every detect step with --probe-out DIR; detect keeps nothing there.
    parser.add_argument("--probe-out")
    args = parser.parse_args()
    try:
        _, path = target_of(args.target)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(json.dumps({"ok": False, "error": str(exc)}))
        return 2
    applies, why, kind = detect(path)
    if args.command == "detect":
        print(json.dumps({"applies": applies, "why": why}))
        return 0 if applies else 1
    if not args.out:
        print(json.dumps({"ok": False, "error": "run needs --out DIR"}))
        return 2
    if not applies:
        print(json.dumps({"ok": False, "status": "unsupported", "why": why}))
        return 2
    rc = run(path, kind, args.out)
    if rc == 2:
        return rc
    status = json.load(open(os.path.join(os.path.abspath(args.out), "coverage.json"), encoding="utf-8")).get("status")
    print(json.dumps({"ok": rc == 0, "status": status}))
    return rc


if __name__ == "__main__":
    sys.exit(main())
