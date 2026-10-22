#!/usr/bin/env python3
"""collection-intake: what a collector's output archive holds, what its own records claim, and whether the members agree.

    run.py detect --target TARGET [--probe-out DIR]   exit 0 applies, 1 does not, 2 could not tell
    run.py run --target TARGET --out DIR              inventory.tsv, records.jsonl, verification.jsonl, units.json, coverage.json

TARGET is JSON (inline or a file path): {"paths": [...], "ref": ..., "name": ...}; the archive is paths[0]: a zip, or a tar plain or
compressed with gzip, bzip2 or xz. It applies when a member is named like a record of a collector: KAPE's `*_CopyLog.csv`,
`*_SkipLog.csv` or `*_ConsoleLog.txt`, UAC's `uac.log` or `hash_executables.*`, Velociraptor's `uploads.json` or
`collection_context.json`. Nothing is extracted to disk: one pass reads the members in order, hashes each (SHA-256, SHA-1 and MD5,
so a record's digest is compared in its own algorithm) and keeps the collector's records in memory or in a temporary file, which are
removed. The records are read by the same adapters collection_manifest_parse uses and joined to the members the way
collection_manifest_verify joins them to files. An archive inside the archive is named and not opened: extract it with
archive_extract (from_index is the number in inventory.tsv) and run this recipe, or the tools, on the result. A 7z is not read here.

    inventory.tsv       n, kind, size, sha256, name (escaped); n counts members in archive order, duplicates included
    records.jsonl       the canonical records, one per row or line of a collector's record, each with the locator of its raw row
    verification.jsonl  one row per delivery claim: path, size and digest checked apart, and the status they add up to
    units.json          the recognised units (a collector's run or container), their sources and their statuses
    coverage.json       the receipt: status, status_basis, the counts, and what this run did not cover

It does not say the archive is authentic or complete as acquired, that a record is true, or what the collector was asked to take.
Every claim in a record is the collector's. Run as a recipe, its outputs are sealed; a name or a record that holds a secret is in
them whole, as in the archive itself.
"""
import argparse
import hashlib
import io
import json
import os
import signal
import sys
import tarfile
import tempfile
import time
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
MAX_MEMBERS = 2000000
MAX_KEPT_BYTES = 1 << 30           # a record kept in full for parsing; a larger one is not parsed and the run says so
DEADLINE = [None]
WITHHELD = {"count": 0}
VALUES = [None]


def out_of_time():
    return DEADLINE[0] is not None and time.monotonic() > DEADLINE[0]


def describe(exc):
    return "%s: %s" % (type(exc).__name__, exc)


# ---- BEGIN RECORDS BLOCK ---------------------------------------------------------------------------------------------
# Identical in collection_manifest_parse, collection_manifest_verify, collection_path_map, collection_coverage and the
# collection_intake recipe (the recipe defines out_of_time, describe, WITHHELD and VALUES before it). A tool is standalone, so what they share is
# copied, and tests/pack-triage-records.test.ts holds the copies equal. Edit it in all of them, never in one. It holds: the
# census of a delivered tree (or of an archive's members), the adapters that read a collector's own records into canonical
# records (KAPE copy, skip and console logs, UAC's log and hash lists, a Velociraptor container), the join of a record to the
# delivered file it names, the hash of a file in one pass, the glob the callers' patterns use, and the name hint for a
# credential store. It prints nothing, and the strings it returns are the caller's to withhold (the tables do); only the digest of a
# credential store is withheld here. It needs `out_of_time()`, `describe(exc)`, `WITHHELD` and `VALUES`.
import collections
import csv
import hashlib
import io
import json
import os
import re
import stat

MAX_CENSUS = 2000000              # entries held for the join; past it the census is partial and no record is called missing
REC_LINE = 1 << 20                # a log line longer than this is read in part; the whole line stays in the evidence at its locator
REC_CHUNK = 1 << 20
REC_FIRST = 25                    # problems of a source kept in its summary; every one goes to the caller's sink
MAX_CONSECUTIVE_BAD_ROWS = 1000
INSIDE_COLLECTED = ("[root]", "uploads")        # a directory below which the files are the source host's own
UAC_EVENT = re.compile(r"^\s*\[?(?P<ts>\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:\s?(?:Z|[+-]\d{2}:?\d{2}))?)\]?\s*"
                       r"(?:[-:|]\s*)?\[?(?P<level>INFO|INF|WARNING|WARN|ERROR|ERR|COMMAND|CMD|DEBUG|DBG)\]?(?:\s|:|$)")
UAC_ERROR_LEVELS = ("ERROR", "ERR")
UAC_COMMAND_LEVELS = ("COMMAND", "CMD")
CONSOLE_LINE = re.compile(r"^\[(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:\.\d+)?) \| (?P<level>[A-Z]{3})\] ")
UPLOAD_MARKERS = ("StoredName", "UploadId", "StoredSize", "Components")
UPLOAD_PATH_KEYS = ("Path", "OSPath", "SourceFile", "FullPath", "vfs_path")
LOG_LEVEL_WORDS = ("TRACE", "DEBUG", "DEFAULT", "INFO", "WARN", "WARNING", "ERROR", "FATAL", "CRITICAL")
HASH_LENGTHS = {32: "md5", 40: "sha1", 64: "sha256"}
HASH_LIST_NAMES = {"hash_executables.md5": "md5", "hash_executables.sha1": "sha1", "hash_executables.sha256": "sha256"}
HASH_LINE = re.compile(r"^(?P<hex>[0-9A-Fa-f]{32}|[0-9A-Fa-f]{40}|[0-9A-Fa-f]{64})[ \t]+\*?(?P<path>.+)$")
HASH_LINE_BSD = re.compile(r"^(?P<tag>MD5|SHA1|SHA256) \((?P<path>.+)\) = (?P<hex>[0-9A-Fa-f]{32,64})$")
KAPE_COPY_KNOWN = ("copiedtimestamp", "sourcefile", "destinationfile", "filesize", "sourcefilesha1", "deferredcopy", "createdonutc",
                   "modifiedonutc", "lastaccessedonutc", "copyduration")
KAPE_COPY_MAPPED = ("copiedtimestamp", "sourcefile", "destinationfile", "filesize", "sourcefilesha1", "createdonutc", "modifiedonutc", "lastaccessedonutc")
KAPE_SKIP_KNOWN = ("sourcefile", "sourcefilesha1", "reason")
SKIP_TARGET_COLUMNS = ("sourcefile", "source", "filename", "file", "path")
SKIP_REASON_COLUMNS = ("reason", "message", "error", "status")
ADAPTERS = {
    "kape_copy_log": {"id": "kape_copy_log/2", "collector": "KAPE", "reads": "*_CopyLog.csv",
                      "schema": "a header with SourceFile and DestinationFile; the other columns KAPE writes are kept by name"},
    "kape_skip_log": {"id": "kape_skip_log/2", "collector": "KAPE", "reads": "*_SkipLog.csv",
                      "schema": "a header with a target column (SourceFile) or a reason column (Reason)"},
    "kape_console_log": {"id": "kape_console_log/1", "collector": "KAPE", "reads": "*_ConsoleLog.txt",
                         "schema": "lines of the form [date time | LVL] text; warnings and errors are rows, none is a failure"},
    "uac_log": {"id": "uac_log/2", "collector": "UAC", "reads": "uac.log",
                "schema": "lines that start with a date, a time and a level word (UAC 3.4.0: DBG INF ERR CMD; 2.9.1: DEBUG INFO WARNING ERROR COMMAND)"},
    "hash_list": {"id": "hash_list/1", "collector": "UAC", "reads": "hash_executables.md5, .sha1, .sha256",
                  "schema": "one 'hex  path' line per file (the md5sum, sha1sum and sha256sum forms) or 'ALGORITHM (path) = hex'"},
    "velociraptor_container": {"id": "velociraptor_container/2", "collector": "Velociraptor", "reads": "uploads.json, results/*.json, log.json, collection_context.json",
                               "schema": "the container 0.77.2 writes: uploads.json rows (vfs_path, file_size, uploaded_size, Type), result rows with an upload record, log.json rows"},
    "cylr": {"id": None, "collector": "CyLR", "reads": None, "supported": False,
             "schema": "none: no record of CyLR is read; a CyLR archive is a tree of copied files, and a top-level C or C$ directory is a layout clue, not a manifest"},
}


# ---- the census: what a delivery holds, by name -------------------------------------------------------------------------


class Census:
    """The relative path, size and kind (f regular file, l link, s special) of every entry of a delivered tree or of an archive's
    members, keyed by the case-folded path so that a record's claim is joined to the file it names whatever the case. Links and
    special files are recorded and never followed. `complete` is false when a directory could not be listed, an entry could not be
    examined, the walk stopped or the cap was reached: a record that names no file is then unverifiable, never missing."""

    def __init__(self, cap=MAX_CENSUS):
        self.cap = cap
        self.by_key = {}
        self.total = self.files = self.dirs = self.links = self.special = 0
        self.capped = False
        self.complete = True
        self.errors = []
        self.errors_total = 0
        self.stopped = None
        self.marked_dirs = []             # directories (and links) named [root]: UAC's directory of collected files

    @staticmethod
    def key(rel):
        return rel.replace(os.sep, "/").casefold()

    def add(self, rel, size, kind):
        if self.total >= self.cap:
            self.capped = True
            self.complete = False
            return
        self.total += 1
        if kind == "f":
            self.files += 1
        elif kind == "l":
            self.links += 1
        else:
            self.special += 1
        self.by_key.setdefault(self.key(rel), []).append((rel, size, kind))

    def error(self, rel, what, exc=None):
        self.complete = False
        self.errors_total += 1
        if len(self.errors) < REC_FIRST:
            self.errors.append({"path": rel, "what": what, **({"error": describe(exc)} if exc is not None else {})})

    def entries(self):
        for group in self.by_key.values():
            for item in group:
                yield item

    def lookup(self, rel):
        return self.by_key.get(self.key(rel), [])


def walk_census(root, census, skip=None):
    """Everything below `root`, one pass, without following a link. `skip(entry)` leaves out the files this run itself writes."""
    prefix = root.rstrip(os.sep) + os.sep
    stack = [root]
    seen = 0
    while stack:
        if out_of_time():
            census.stopped = {"reason": "the time limit ended the walk", "directories_not_listed": len(stack)}
            census.complete = False
            return
        directory = stack.pop()
        rel_dir = directory[len(prefix):] if directory.startswith(prefix) else ""
        try:
            with os.scandir(directory) as it:
                entries = list(it)
        except OSError as exc:
            census.error(rel_dir or ".", "the directory could not be listed", exc)
            continue
        census.dirs += 1
        for entry in entries:
            seen += 1
            if (seen & 1023) == 0 and out_of_time():
                census.stopped = {"reason": "the time limit ended the walk", "directories_not_listed": len(stack)}
                census.complete = False
                return
            if skip is not None and skip(entry):
                continue
            rel = entry.path[len(prefix):] if entry.path.startswith(prefix) else os.path.relpath(entry.path, root)
            try:
                st = entry.stat(follow_symlinks=False)
            except OSError as exc:
                census.error(rel, "the entry could not be examined", exc)
                continue
            mode = st.st_mode
            if stat.S_ISLNK(mode):
                census.add(rel, 0, "l")
                if entry.name == "[root]":
                    census.marked_dirs.append(rel)
            elif stat.S_ISDIR(mode):
                stack.append(entry.path)
                if entry.name == "[root]":
                    census.marked_dirs.append(rel)
            elif stat.S_ISREG(mode):
                census.add(rel, st.st_size, "f")
            else:
                census.add(rel, 0, "s")


class DirSource:
    """A delivered directory as a source of bytes: a regular file is opened without following a link at its name and without
    blocking on a pipe; anything else is refused."""
    kind = "directory"

    def __init__(self, root):
        self.root = root

    def path(self, rel):
        return os.path.join(self.root, rel)

    def open_binary(self, rel):
        fd = os.open(self.path(rel), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                raise OSError(22, "not a regular file")
            return os.fdopen(fd, "rb")
        except BaseException:
            os.close(fd)
            raise

    def head(self, rel, count=4096):
        with self.open_binary(rel) as fh:
            return fh.read(count)


def open_text(src, rel):
    return io.TextIOWrapper(src.open_binary(rel), encoding="utf-8-sig", errors="surrogateescape", newline="")


def undecodable(text):
    return any("\udc80" <= c <= "\udcff" for c in text)


def binary_reason(src, rel):
    """Why a log cannot be read as UTF-8 text at all (a UTF-16 byte-order mark, or NUL bytes in its first 4 KiB), or None."""
    try:
        head = src.head(rel)
    except OSError:
        return None
    if head[:2] in (b"\xff\xfe", b"\xfe\xff"):
        return "the file is UTF-16 (byte-order mark): it is not read as UTF-8 text"
    if b"\x00" in head:
        return "the file holds NUL bytes in its first 4 KiB: it is binary or UTF-16 without a mark, and is not read as text"
    return None


def inside_collected_data(rel):
    return any(part in INSIDE_COLLECTED for part in rel.split("/")[:-1]) or any(part in INSIDE_COLLECTED for part in rel.split(os.sep)[:-1])


def parent_of(rel):
    cut = max(rel.rfind("/"), rel.rfind(os.sep))
    return rel[:cut] if cut >= 0 else ""


def name_of(rel):
    return rel[max(rel.rfind("/"), rel.rfind(os.sep)) + 1:]


def join_rel(*parts):
    return "/".join(p for p in parts if p)


def discover(census):
    """The collectors' records among the files of a census, by name: KAPE runs (a directory and a run id), UAC logs and hash
    lists, Velociraptor containers (a directory with uploads.json or collection_context.json, its results/*.json and its
    log.json). A record found inside collected data (below [root] or uploads) belongs to the source host and is listed apart,
    never read. Sorted by the name's bytes, so a run reads the same records in the same order every time."""
    found = {"kape": {}, "uac_logs": [], "uac_hashes": [], "uac_dirs": [], "velociraptor": {}, "velo_results": {}, "velo_logs": {}, "inside_collected": []}
    for rel, size, kind in sorted((e for e in census.entries() if e[2] == "f"), key=lambda e: os.fsencode(e[0])):
        name = name_of(rel)
        low = name.lower()
        directory = parent_of(rel)
        marker = None
        for suffix, key in (("_copylog.csv", "copy"), ("_skiplog.csv", "skip"), ("_consolelog.txt", "console")):
            if low.endswith(suffix):
                marker = ("kape", key, name[:-len(suffix)])
        if name == "uac.log":
            marker = ("uac", None, None)
        elif low in HASH_LIST_NAMES:
            marker = ("uac_hash", None, None)
        elif name in ("uploads.json", "collection_context.json"):
            marker = ("velociraptor", "uploads" if name == "uploads.json" else "context", None)
        elif name.endswith(".json") and name_of(directory) == "results":
            marker = ("velo_result", None, None)
        elif name == "log.json":
            marker = ("velo_log", None, None)
        if marker is None:
            continue
        if inside_collected_data(rel):
            if marker[0] in ("kape", "uac", "uac_hash", "velociraptor"):
                found["inside_collected"].append(rel)
            continue
        if marker[0] == "kape":
            found["kape"].setdefault((directory, marker[2]), {})[marker[1]] = rel
        elif marker[0] == "uac":
            found["uac_logs"].append(rel)
        elif marker[0] == "uac_hash":
            found["uac_hashes"].append(rel)
        elif marker[0] == "velociraptor":
            found["velociraptor"].setdefault(directory, {})[marker[1]] = rel
        elif marker[0] == "velo_result":
            found["velo_results"].setdefault(parent_of(directory), []).append(rel)
        else:
            found["velo_logs"][directory] = rel
    found["uac_dirs"] = sorted(census.marked_dirs, key=os.fsencode)
    return found


# ---- the adapters: a collector's own record, one canonical record per row ------------------------------------------------


class Sink:
    """Where an adapter puts what it reads. A tool subclasses it to write tables; the default keeps the lists."""

    def __init__(self):
        self.records = []
        self.problems = []
        self.count = 0

    def record(self, rec):
        self.count += 1
        rec["n"] = self.count
        self.records.append(rec)

    def problem(self, row):
        self.problems.append(row)


def new_source(rel, collector, adapter, kind, **extra):
    return {"log": rel, "collector": collector, "kind": kind, "adapter": ADAPTERS[adapter]["id"], "status": "parsed", "rows": 0, "records": 0,
            "malformed_rows": 0, "problems_total": 0, "problems": [], **extra}


def note(sink, source, locator, error, **extra):
    source["problems_total"] += 1
    row = {"log": source["log"], "locator": locator, "error": error, **extra}
    if len(source["problems"]) < REC_FIRST:
        source["problems"].append({"locator": locator, "error": error})
    sink.problem(row)


def emit(sink, source, run, base, **fields):
    source["records"] += 1
    rec = {"collector": source["collector"], "run": run, "directory": base or ".", "adapter": source["adapter"], "log": source["log"]}
    rec.update(fields)
    sink.record(rec)


def whole_int(text):
    if isinstance(text, bool):
        return None
    if isinstance(text, int):
        return text if text >= 0 else None
    if isinstance(text, str) and re.fullmatch(r"[0-9]{1,20}", text.strip()):
        return int(text.strip())
    return None


def hash_claim(algorithm, value):
    """The lower-case hex of a digest of the length its algorithm has, else None (the raw text stays in the row's fields). A row's
    claims are a dictionary of algorithm to digest: the key says which algorithm the collector used, and no digest is read as another."""
    if not isinstance(value, str):
        return None
    value = value.strip()
    if not value or not re.fullmatch(r"[0-9A-Fa-f]+", value):
        return None
    want = {"md5": 32, "sha1": 40, "sha256": 64}.get(algorithm)
    if want is None or len(value) != want:
        return None
    return value.lower()


def read_kape_csv(src, rel, kind, run, base, sink):
    """A KAPE copy or skip log, streamed. A copy-log row becomes a `copy` record (the source path, the destination path, the size,
    the SHA-1 of the source and the times, each as the collector wrote it, and the whole row by column name); a skip-log row a
    `skip` record with the collector's own words. A header without the columns an adapter needs is `partial` (copy log: rows are
    counted, nothing else is read) and a log that is binary, UTF-16 or unreadable `unsupported` or `unreadable`."""
    adapter = "kape_copy_log" if kind == "copy" else "kape_skip_log"
    source = new_source(rel, "KAPE", adapter, kind + "_log", run=run, directory=base or ".", columns=[], unrecognised_columns=[], rows_with_undecodable_bytes=0)
    reason = binary_reason(src, rel)
    if reason:
        source.update(status="unsupported", reason=reason)
        return source
    try:
        fh = open_text(src, rel)
    except OSError as exc:
        source.update(status="unreadable", reason=describe(exc))
        return source
    csv.field_size_limit(REC_LINE)
    with fh:
        reader = csv.reader(fh, strict=True)
        try:
            header = next(reader)
        except StopIteration:
            source.update(status="unsupported", reason="the file is empty: no header row")
            return source
        except (csv.Error, OSError) as exc:
            source.update(status="unsupported", reason="the header row could not be read (%s)" % describe(exc))
            return source
        names = [h.strip() for h in header]
        lowered = [n.lower() for n in names]
        source["columns"] = names
        known = KAPE_COPY_KNOWN if kind == "copy" else KAPE_SKIP_KNOWN
        source["unrecognised_columns"] = [n for n, low in zip(names, lowered) if low not in known]
        column = {low: i for i, low in reversed(list(enumerate(lowered)))}
        recognised = True
        if kind == "copy":
            if "sourcefile" not in column:
                recognised = False
                source.update(status="partial", reason="no SourceFile column: rows are counted, nothing else is read")
        elif not any(c in column for c in SKIP_TARGET_COLUMNS + SKIP_REASON_COLUMNS):
            recognised = False
            source.update(status="partial", reason="neither a target column nor a reason column is recognised: every row is kept whole in "
                          "unrecognised_row records, and none is a failure")
        target_col = next((column[c] for c in SKIP_TARGET_COLUMNS if c in column), None)
        reason_col = next((column[c] for c in SKIP_REASON_COLUMNS if c in column), None)

        def cell(row, name):
            i = column.get(name)
            return row[i] if i is not None and i < len(row) else None

        ordinal, consecutive = 0, 0
        while True:
            if out_of_time():
                source.update(status="partial", reason="the time limit stopped the read after row %d" % ordinal)
                break
            start_line = reader.line_num + 1                  # a record can span lines (a quoted newline): its locator is the line it starts on
            try:
                row = next(reader)
            except StopIteration:
                break
            except csv.Error as exc:
                source["malformed_rows"] += 1
                consecutive += 1
                note(sink, source, {"line": start_line}, describe(exc))
                if consecutive >= MAX_CONSECUTIVE_BAD_ROWS:
                    source.update(status="partial", reason="the read stopped after %d consecutive unreadable rows" % consecutive)
                    break
                continue
            consecutive = 0
            if not row:
                continue
            ordinal += 1
            source["rows"] = ordinal
            bad = len(row) != len(names)
            if bad:
                source["malformed_rows"] += 1
                note(sink, source, {"line": start_line, "row": ordinal}, "%d fields where the header has %d" % (len(row), len(names)))
            if any(undecodable(v) for v in row):
                source["rows_with_undecodable_bytes"] += 1
            fields = {n: v for n, v in zip(names, row)}
            locator = {"log": rel, "row": ordinal, "line": start_line}
            flags = ["malformed_row"] if bad else []
            if not recognised:
                emit(sink, source, run, base, kind="unrecognised_row", outcome="recorded", locator=locator, fields=fields, flags=flags)
            elif kind == "copy":
                size_raw = cell(row, "filesize")
                claim = hash_claim("sha1", cell(row, "sourcefilesha1"))
                emit(sink, source, run, base, kind="copy", outcome="copied", locator=locator,
                     source_path_claim=cell(row, "sourcefile"), delivered_path_claim=cell(row, "destinationfile"),
                     size_claim=whole_int(size_raw), hash_claims={"sha1": claim} if claim else {},
                     times={n: v for n, v in zip(names, row) if n.lower() in ("copiedtimestamp", "createdonutc", "modifiedonutc", "lastaccessedonutc")},
                     fields={n: v for n, v in fields.items() if n.lower() not in KAPE_COPY_MAPPED}, flags=flags + (["size_not_a_whole_number"] if size_raw not in (None, "") and whole_int(size_raw) is None else []) +
                     (["hash_claim_not_a_digest"] if cell(row, "sourcefilesha1") not in (None, "") and not claim else []))
            else:
                target = row[target_col] if target_col is not None and target_col < len(row) else None
                why = row[reason_col] if reason_col is not None and reason_col < len(row) else None
                claim = hash_claim("sha1", cell(row, "sourcefilesha1"))
                emit(sink, source, run, base, kind="skip", outcome="skipped", locator=locator, source_path_claim=target, delivered_path_claim=None,
                     reason=why, hash_claims={"sha1": claim} if claim else {},
                     fields={n: v for n, v in fields.items() if n.lower() not in KAPE_SKIP_KNOWN}, flags=flags)
        if source["malformed_rows"] and source["status"] == "parsed":
            source["status"] = "partial"
            source["reason"] = "some rows are malformed (see problems): each is a record with the flag malformed_row"
    return source


def read_console(src, rel, run, base, sink):
    """A KAPE console log: its levelled lines are counted by level, and a warning or an error is a record (a recorded line of the
    collector's own, never a failure count: it says what the collector wrote, not that a target was lost)."""
    source = new_source(rel, "KAPE", "kape_console_log", "console_log", run=run, directory=base or ".", lines=0, levels={}, unmatched_lines=0)
    reason = binary_reason(src, rel)
    if reason:
        source.update(status="unsupported", reason=reason)
        return source
    try:
        fh = open_text(src, rel)
    except OSError as exc:
        source.update(status="unreadable", reason=describe(exc))
        return source
    with fh:
        number = 0
        while True:
            if out_of_time():
                source.update(status="partial", reason="the time limit stopped the read after line %d" % number)
                break
            try:
                line = fh.readline(REC_LINE)
            except OSError as exc:
                source.update(status="partial", reason="the read stopped at line %d (%s)" % (number + 1, describe(exc)))
                break
            if not line:
                break
            number += 1
            source["lines"] = number
            if len(line) == REC_LINE and not line.endswith("\n"):
                while True:
                    rest = fh.readline(REC_LINE)
                    if not rest or rest.endswith("\n"):
                        break
            text = line.rstrip("\r\n")
            found = CONSOLE_LINE.match(text)
            if found:
                level = found.group("level")
                source["levels"][level] = source["levels"].get(level, 0) + 1
                if level in ("WRN", "ERR"):
                    emit(sink, source, run, base, kind="log_event", outcome="warning" if level == "WRN" else "error", counts_as_failure=False,
                         locator={"log": rel, "line": number}, text=text)
            elif text.strip():
                source["unmatched_lines"] += 1
    if source["unmatched_lines"] and source["status"] == "parsed":
        source["status"] = "partial"
        source["reason"] = ("%d line(s) match no levelled shape this adapter knows (a wrapped message, a banner, another version's form): "
                            "counted, never read as levelled" % source["unmatched_lines"])
    return source


def read_uac_log(src, rel, sink):
    """UAC's log, streamed. A line with an ERR or ERROR level is a record and a failure; a command's stderr line is counted apart;
    a line that matches no event shape is counted and kept unlabelled (never a failure); a summary that says 0 errors is not one."""
    base = parent_of(rel)
    source = new_source(rel, "UAC", "uac_log", "uac_log", run=base or ".", directory=base or ".", lines=0, events=0, levels={}, unmatched_lines=0, command_stderr_lines=0,
                        long_lines=0, unlabelled_lines_with_failure_words=0)
    reason = binary_reason(src, rel)
    if reason:
        source.update(status="unsupported", reason=reason)
        return source
    try:
        fh = io.TextIOWrapper(src.open_binary(rel), encoding="utf-8", errors="surrogateescape", newline="")
    except OSError as exc:
        source.update(status="unreadable", reason=describe(exc))
        return source
    with fh:
        number = 0
        while True:
            if out_of_time():
                source.update(status="partial", reason="the time limit stopped the read after line %d" % number)
                break
            try:
                line = fh.readline(REC_LINE)
            except OSError as exc:
                source.update(status="partial", reason="the read stopped at line %d (%s)" % (number + 1, describe(exc)))
                break
            if not line:
                break
            number += 1
            long_line = len(line) == REC_LINE and not line.endswith("\n")
            if long_line:
                source["long_lines"] += 1
                while True:
                    rest = fh.readline(REC_LINE)
                    if not rest or rest.endswith("\n"):
                        break
            source["lines"] = number
            text = line.rstrip("\r\n")
            low = text.lower()
            found = UAC_EVENT.match(text)
            if found:
                source["events"] += 1
                level = found.group("level")
                source["levels"][level] = source["levels"].get(level, 0) + 1
                if level in UAC_ERROR_LEVELS:
                    emit(sink, source, run=base or ".", base=base, kind="log_event", outcome="error", counts_as_failure=True,
                         locator={"log": rel, "line": number}, text=text, flags=["long_line"] if long_line else [])
                elif level in UAC_COMMAND_LEVELS and " 2> " in text:
                    source["command_stderr_lines"] += 1
            elif text.strip():
                source["unmatched_lines"] += 1
                if any(w in low for w in ("error", "cannot", "permission denied", "failed", "no such file")):
                    source["unlabelled_lines_with_failure_words"] += 1
                    note(sink, source, {"line": number}, "a line with a failure word that matches no event shape: counted, never a failure", text=text)
    if source["status"] == "parsed" and source["events"] == 0:
        source["status"] = "unsupported"
        source["reason"] = "no line starts with a date, a time and a level word this adapter knows: failures are not counted from this log"
    elif source["status"] == "parsed" and source["unmatched_lines"]:
        source["status"] = "partial"
        source["reason"] = "%d line(s) match no recognised event shape: counted, kept unlabelled, never counted as failures" % source["unmatched_lines"]
    return source


def read_hash_list(src, rel, sink):
    """One 'digest  path' line per file (the md5sum, sha1sum and sha256sum forms, or 'ALGORITHM (path) = digest'). Each line is a
    `hash_claim` record: a claim about a file of the source host, named by its path there; whether the delivery holds that file
    is the join's to say. The algorithm is read from the digest's length and checked against the list's name."""
    base = parent_of(rel)
    if name_of(base) == "hash_executables":                  # UAC writes the list in its own directory beside [root]
        base = parent_of(base)
    expected = HASH_LIST_NAMES.get(name_of(rel).lower())
    source = new_source(rel, "UAC", "hash_list", "hash_list", run=base or ".", directory=base or ".", lines=0, algorithm=expected, unmatched_lines=0)
    reason = binary_reason(src, rel)
    if reason:
        source.update(status="unsupported", reason=reason)
        return source
    try:
        fh = io.TextIOWrapper(src.open_binary(rel), encoding="utf-8", errors="surrogateescape", newline="")
    except OSError as exc:
        source.update(status="unreadable", reason=describe(exc))
        return source
    with fh:
        number = 0
        while True:
            if out_of_time():
                source.update(status="partial", reason="the time limit stopped the read after line %d" % number)
                break
            try:
                line = fh.readline(REC_LINE)
            except OSError as exc:
                source.update(status="partial", reason="the read stopped at line %d (%s)" % (number + 1, describe(exc)))
                break
            if not line:
                break
            number += 1
            source["lines"] = number
            if len(line) == REC_LINE and not line.endswith("\n"):
                while True:
                    rest = fh.readline(REC_LINE)
                    if not rest or rest.endswith("\n"):
                        break
            text = line.rstrip("\r\n")
            if not text.strip():
                continue
            found = HASH_LINE.match(text)
            digest = path = None
            if found:
                digest, path = found.group("hex"), found.group("path")
            else:
                bsd = HASH_LINE_BSD.match(text)
                if bsd:
                    digest, path = bsd.group("hex"), bsd.group("path")
            if digest is None:
                source["unmatched_lines"] += 1
                continue
            algorithm = HASH_LENGTHS.get(len(digest))
            flags = []
            if expected and algorithm != expected:
                flags.append("digest_length_disagrees_with_the_list_name")
                note(sink, source, {"line": number}, "a %d-character digest in a list named for %s" % (len(digest), expected))
            claim = hash_claim(algorithm, digest) if algorithm else None
            emit(sink, source, run=base or ".", base=base, kind="hash_claim", outcome="recorded", locator={"log": rel, "line": number},
                 source_path_claim=path, delivered_path_claim=None, hash_claims={algorithm: claim} if claim else {}, flags=flags)
    if source["unmatched_lines"] and source["status"] == "parsed":
        source["status"] = "partial"
        source["reason"] = "%d line(s) are not a digest and a path: counted, read as nothing" % source["unmatched_lines"]
    return source


def jsonl_rows(fh, source, sink, label):
    """(line number, row) for each JSON object of a JSON Lines stream; a line that is not valid JSON, not an object, or too long
    is counted and located and the stream goes on. A JSON array is not JSON Lines: it ends the stream with `unsupported`."""
    number = 0
    first = True
    while True:
        if out_of_time():
            source.update(status="partial", reason="the time limit stopped the read of %s after line %d" % (label, number))
            return
        try:
            line = fh.readline(REC_LINE)
        except OSError as exc:
            source.update(status="partial", reason="the read of %s stopped at line %d (%s)" % (label, number + 1, describe(exc)))
            return
        if not line:
            return
        number += 1
        if len(line) == REC_LINE and not line.endswith("\n"):
            source["malformed_rows"] += 1
            note(sink, source, {"file": label, "line": number}, "a line longer than %d bytes: read no further" % REC_LINE)
            while True:
                rest = fh.readline(REC_LINE)
                if not rest or rest.endswith("\n"):
                    break
            continue
        if not line.strip():
            continue
        if first and line.lstrip().startswith("["):
            source.update(status="unsupported", reason="%s is a JSON array, not JSON Lines: nothing was read from it" % label)
            return
        first = False
        try:
            row = json.loads(line)
        except (ValueError, RecursionError):
            source["malformed_rows"] += 1
            note(sink, source, {"file": label, "line": number}, "not valid JSON")
            continue
        if not isinstance(row, dict):
            source["non_object_rows"] += 1
            note(sink, source, {"file": label, "line": number}, "a JSON line that is not an object")
            continue
        yield number, row


def upload_records(value, depth=0):
    """Every upload record under `value`: a dictionary with a key only an upload record has (StoredName, UploadId, StoredSize,
    Components). Velociraptor puts an upload in a result row as a nested record."""
    if depth > 4:
        return
    if isinstance(value, dict):
        if any(k in value for k in UPLOAD_MARKERS):
            yield value
            return
        for child in value.values():
            yield from upload_records(child, depth + 1)
    elif isinstance(value, list):
        for child in value[:1000]:
            yield from upload_records(child, depth + 1)


def has_error(value):
    err = value.get("Error")
    return err not in (None, "", [], {})


def text_of(value):
    return value if isinstance(value, str) else json.dumps(value, ensure_ascii=False, default=str)


def claims_of(upload):
    """The digests a Velociraptor upload record carries, under the key spellings its versions use."""
    out = {}
    for algorithm, keys in (("sha256", ("sha256", "Sha256", "SHA256")), ("md5", ("md5", "Md5", "MD5")), ("sha1", ("sha1", "Sha1", "SHA1"))):
        for key in keys:
            if isinstance(upload.get(key), str) and upload[key].strip():
                claim = hash_claim(algorithm, upload[key])
                if claim:
                    out[algorithm] = claim
                break
    return out


def read_velociraptor(src, directory, files, found, sink):
    """One Velociraptor collection container: a directory holding uploads.json and/or collection_context.json. The version this
    pack pins writes a failed upload to no row of uploads.json: it is a result row's upload record with an Error, and an ERROR line
    of log.json. So the container is read whole only when results/*.json and log.json were read as well, and a source that is not
    there makes the container `partial`: the outcomes it would have recorded are unknown, which is not zero."""
    anchor = files.get("uploads") or files.get("context")
    source = new_source(anchor, "Velociraptor", "velociraptor_container", "velociraptor_container", run=directory or ".", directory=directory or ".", container=directory or ".",
                        sources={}, non_object_rows=0, uploads_rows=0, rows_stored_smaller_than_file=0, result_rows=0, upload_records=0,
                        rows_with_upload_error=0, log_levels={}, error_lines=0, warning_lines=0, artefacts={})
    partial = []

    def part(name, status, **extra):
        source["sources"][name] = {"status": status, **extra}
        if status != "parsed":
            partial.append("%s is %s" % (name, status))

    def sub_status(sub):
        if sub["status"] != "parsed":
            return sub["status"]
        return "partial" if sub["malformed_rows"] or sub["non_object_rows"] else "parsed"

    def sub_of():
        return {"log": source["log"], "status": "parsed", "malformed_rows": 0, "non_object_rows": 0, "problems": source["problems"], "problems_total": 0}

    def fold(sub):
        source["malformed_rows"] += sub["malformed_rows"]
        source["non_object_rows"] += sub["non_object_rows"]
        source["problems_total"] += sub["problems_total"]

    if files.get("uploads"):
        rel = files["uploads"]
        reason = binary_reason(src, rel)
        if reason:
            part("uploads.json", "unsupported", reason=reason)
        else:
            sub = sub_of()
            try:
                fh = open_text(src, rel)
            except OSError as exc:
                part("uploads.json", "unreadable", reason=describe(exc))
            else:
                with fh:
                    for number, row in jsonl_rows(fh, sub, sink, "uploads.json"):
                        source["uploads_rows"] += 1
                        size, stored = row.get("file_size"), row.get("uploaded_size")
                        flags = []
                        if isinstance(size, int) and isinstance(stored, int) and stored < size and row.get("Type") != "idx":
                            source["rows_stored_smaller_than_file"] += 1
                            flags.append("stored_smaller_than_file")
                        if row.get("Type") == "idx":
                            flags.append("sparse_index")
                        vfs = row.get("vfs_path")
                        emit(sink, source, directory or ".", directory, kind="upload", outcome="uploaded", locator={"log": rel, "line": number},
                             source_path_claim=None, delivered_path_claim=vfs if isinstance(vfs, str) else None,
                             size_claim=stored if isinstance(stored, int) and not isinstance(stored, bool) and stored >= 0 else None,
                             logical_size_claim=size if isinstance(size, int) and not isinstance(size, bool) and size >= 0 else None,
                             hash_claims={}, times={k: row[k] for k in ("Timestamp", "started") if k in row}, fields=row, flags=flags)
                fold(sub)
                part("uploads.json", sub_status(sub), **({"reason": sub["reason"]} if "reason" in sub else {}))
    else:
        part("uploads.json", "not_found", reason="no uploads.json beside collection_context.json: the container's index of stored files is absent")

    names = sorted(found["velo_results"].get(directory, []), key=os.fsencode)
    if not names:
        part("results/*.json", "not_found", reason="no results/*.json beside the container's index: a failed upload is recorded there in this version")
    else:
        sub = sub_of()
        for rel in names:
            artefact = name_of(rel)[:-len(".json")]
            if len(source["artefacts"]) < 100000:
                source["artefacts"].setdefault(artefact, 0)
            try:
                fh = open_text(src, rel)
            except OSError as exc:
                note(sink, source, {"file": rel}, "a results file could not be opened: %s" % describe(exc))
                sub["status"] = "partial"
                continue
            with fh:
                for number, row in jsonl_rows(fh, sub, sink, name_of(rel)):
                    source["result_rows"] += 1
                    if artefact in source["artefacts"]:
                        source["artefacts"][artefact] += 1
                    for upload in upload_records(row):
                        source["upload_records"] += 1
                        failed = has_error(upload)
                        if failed:
                            source["rows_with_upload_error"] += 1
                        stored_name = upload.get("StoredName")
                        components = upload.get("Components")
                        delivered = stored_name if isinstance(stored_name, str) and stored_name else (
                            "/".join(str(c) for c in components) if isinstance(components, list) and components and all(isinstance(c, (str, int)) for c in components) else None)
                        path = next((upload[k] for k in UPLOAD_PATH_KEYS if isinstance(upload.get(k), str) and upload.get(k)), None)
                        size, stored = upload.get("Size"), upload.get("StoredSize")
                        flags = []
                        if isinstance(size, int) and isinstance(stored, int) and stored < size:
                            flags.append("stored_smaller_than_file")
                        emit(sink, source, directory or ".", directory, kind="upload_result", outcome="upload_error" if failed else "uploaded",
                             counts_as_failure=failed, locator={"log": rel, "line": number}, artefact=artefact, source_path_claim=path,
                             delivered_path_claim=delivered, accessor=upload.get("Accessor") if isinstance(upload.get("Accessor"), str) else None,
                             size_claim=stored if isinstance(stored, int) and not isinstance(stored, bool) and stored >= 0 else None,
                             logical_size_claim=size if isinstance(size, int) and not isinstance(size, bool) and size >= 0 else None,
                             hash_claims=claims_of(upload), reason=text_of(upload.get("Error")) if failed else None, fields=upload, flags=flags)
        fold(sub)
        part("results/*.json", sub_status(sub), files=len(names), **({"reason": sub["reason"]} if "reason" in sub else {}))

    log_rel = found["velo_logs"].get(directory)
    if not log_rel:
        part("log.json", "not_found", reason="no log.json beside the container's index: the collection's own errors are recorded there")
    else:
        sub = sub_of()
        try:
            fh = open_text(src, log_rel)
        except OSError as exc:
            part("log.json", "unreadable", reason=describe(exc))
        else:
            with fh:
                for number, row in jsonl_rows(fh, sub, sink, "log.json"):
                    level = row.get("level")
                    level = level if isinstance(level, str) else "?"
                    word = level.upper() if level.upper() in LOG_LEVEL_WORDS else "other"
                    source["log_levels"][word] = source["log_levels"].get(word, 0) + 1
                    if level.upper() in ("ERROR", "WARN", "WARNING"):
                        is_error = level.upper() == "ERROR"
                        source["error_lines" if is_error else "warning_lines"] += 1
                        emit(sink, source, directory or ".", directory, kind="log_event", outcome="error" if is_error else "warning",
                             counts_as_failure=is_error, locator={"log": log_rel, "line": number}, text=text_of(row.get("message")))
            fold(sub)
            part("log.json", sub_status(sub), **({"reason": sub["reason"]} if "reason" in sub else {}))
    if partial:
        source["status"] = "partial" if any(v["status"] == "parsed" for v in source["sources"].values()) else "unsupported"
        source["reason"] = "; ".join(partial) + ": the failure count is not determined from this container"
    return source


def read_collection(src, found, sink):
    """Every recognised record of a census, in a fixed order: KAPE runs, UAC logs and hash lists, Velociraptor containers. Returns
    the source summaries (one per log, one per container), each with its adapter, its status and why."""
    sources = []
    for (directory, run_id), logs in sorted(found["kape"].items(), key=lambda kv: (os.fsencode(kv[0][0]), os.fsencode(kv[0][1]))):
        run = run_id
        if "copy" in logs:
            sources.append(read_kape_csv(src, logs["copy"], "copy", run, directory, sink))
        if "skip" in logs:
            sources.append(read_kape_csv(src, logs["skip"], "skip", run, directory, sink))
        if "console" in logs:
            sources.append(read_console(src, logs["console"], run, directory, sink))
    for rel in found["uac_logs"]:
        sources.append(read_uac_log(src, rel, sink))
    for rel in found["uac_hashes"]:
        sources.append(read_hash_list(src, rel, sink))
    for directory, files in sorted(found["velociraptor"].items(), key=lambda kv: os.fsencode(kv[0])):
        sources.append(read_velociraptor(src, directory, files, found, sink))
    return sources


# ---- the join: a record to the delivered file it names --------------------------------------------------------------------


def path_parts(text):
    """The components of a path as a collector wrote it, whichever separator, without a drive prefix (C: or C$)."""
    parts = [p for p in re.split(r"[\\/]+", text) if p]
    if parts and re.fullmatch(r"[A-Za-z][:$]", parts[0]):
        parts = parts[1:]
    return parts


def percent_quote(part):
    return part.replace("%", "%25").replace(":", "%3A")


def candidate_paths(rec):
    """The delivered paths (relative to the record's own directory) a record may name, with how each was derived. A KAPE copy row
    names a destination whose tail is the path in the delivered tree; a Velociraptor row a stored name under uploads/; a UAC hash
    list a file of the source host that the collector's [root] directory would hold."""
    collector, kind = rec.get("collector"), rec.get("kind")
    claim = rec.get("delivered_path_claim")
    if collector == "KAPE" and kind == "copy" and isinstance(claim, str):
        return "suffix", path_parts(claim)
    if collector == "Velociraptor" and isinstance(claim, str):
        raw = [p for p in claim.split("/") if p]
        forms = []
        for lead in ((), ("uploads",), ("uploads", "auto")):
            where = "/".join(lead) or "the container"
            forms.append((lead + tuple(raw), "stored name under " + where))
            forms.append((lead + tuple(percent_quote(p) for p in raw), "stored name with the colon and the percent sign escaped, under " + where))
        return "exact", forms
    if collector == "UAC" and kind == "hash_claim" and isinstance(rec.get("source_path_claim"), str):
        parts = [p for p in rec["source_path_claim"].split("/") if p]
        return "exact", [(("[root]",) + tuple(parts), "UAC's [root] convention: a hypothesis, not a record of the collector")]
    return None, None


def resolve(census, rec):
    """{status, rel, matched_by, depth, candidates}: `found` (one file), `ambiguous` (several files differing by case, or only the
    file name matches), `missing` (nothing, and the census is complete), `unknown` (nothing, and the census is not complete), or
    `no_claim`. A link or a special file at the name is `not_regular`. The longest tail of a KAPE destination wins; a tail of one
    component is a weak match and is never `found`."""
    how, spec = candidate_paths(rec)
    base = rec.get("directory") or ""
    base = "" if base == "." else base
    if how is None:
        return {"status": "no_claim", "rel": None, "matched_by": None, "depth": 0, "candidates": []}
    hits = []
    if how == "suffix":
        parts = spec
        if not parts:
            return {"status": "no_claim", "rel": None, "matched_by": None, "depth": 0, "candidates": []}
        for i in range(len(parts)):
            depth = len(parts) - i
            hits = census.lookup(join_rel(base, "/".join(parts[i:])))
            if hits:
                weak = depth == 1 and len(parts) > 1
                return finish(hits, "the destination's last %d component(s) under the log's directory%s" % (depth, " (only the file name matches)" if weak else ""),
                              depth, weak)
    else:
        for parts, why in spec:
            hits = census.lookup(join_rel(base, "/".join(parts)))
            if hits:
                return finish(hits, why, len(parts), False)
    return {"status": "missing" if census.complete else "unknown", "rel": None, "matched_by": None, "depth": 0, "candidates": []}


def finish(hits, why, depth, weak):
    rels = sorted({h[0] for h in hits}, key=os.fsencode)
    regular = [h for h in hits if h[2] == "f"]
    if weak:
        return {"status": "ambiguous", "rel": rels[0] if len(rels) == 1 else None, "matched_by": why, "depth": depth, "candidates": rels[:REC_FIRST],
                "reason": "only the file name matches"}
    if len(rels) > 1:
        return {"status": "ambiguous", "rel": None, "matched_by": why, "depth": depth, "candidates": rels[:REC_FIRST],
                "reason": "%d delivered files differ from each other only by case" % len(rels)}
    if len(hits) > len(rels):
        return {"status": "ambiguous", "rel": None, "matched_by": why, "depth": depth, "candidates": rels[:REC_FIRST],
                "reason": "the name appears %d times (an archive can hold one name twice)" % len(hits)}
    if not regular:
        return {"status": "not_regular", "rel": rels[0], "matched_by": why, "depth": depth, "candidates": rels,
                "reason": "the delivered entry is a link or a special file: it is not followed"}
    return {"status": "found", "rel": rels[0], "size": regular[0][1], "matched_by": why, "depth": depth, "candidates": rels}


# ---- hashing a delivered file in one pass ------------------------------------------------------------------------------------


class HashStopped(Exception):
    def __init__(self, read):
        super().__init__("the time limit ended the read")
        self.read = read


def digest_object(name):
    try:
        return hashlib.new(name, usedforsecurity=False)
    except (TypeError, ValueError):
        try:
            return hashlib.new(name)
        except ValueError:
            return None


def hash_file(src, rel, algorithms):
    """{algorithm: hex} for the algorithms asked, always with sha256 (an independent digest beside the collector's own), and the
    bytes read, in one pass over the file. An algorithm this Python does not have is left out. Raises OSError, or HashStopped
    when the time limit ends the read."""
    wanted = ["sha256"] + [a for a in algorithms if a != "sha256"]
    objects = {a: digest_object(a) for a in wanted}
    objects = {a: o for a, o in objects.items() if o is not None}
    total = 0
    with src.open_binary(rel) as fh:
        while True:
            block = fh.read(REC_CHUNK)
            if not block:
                break
            total += len(block)
            for o in objects.values():
                o.update(block)
            if out_of_time():
                raise HashStopped(total)
    return {a: o.hexdigest() for a, o in objects.items()}, total


# ---- patterns the callers' questions use ---------------------------------------------------------------------------------------


def norm_text(text):
    return text.replace("\\", "/").casefold()


def glob_match(pattern, text):
    """`*` (any run, `/` included) and `?` (one character) over case-folded text with `/` for either separator: no regular
    expression, so a pattern cannot be made to take exponential time; the cost is at most the product of the two lengths."""
    p = t = 0
    star = -1
    mark = 0
    while t < len(text):
        if p < len(pattern) and (pattern[p] == "?" or pattern[p] == text[t]):
            p += 1
            t += 1
        elif p < len(pattern) and pattern[p] == "*":
            star = p
            mark = t
            p += 1
        elif star != -1:
            p = star + 1
            mark += 1
            t = mark
        else:
            return False
    while p < len(pattern) and pattern[p] == "*":
        p += 1
    return p == len(pattern)




# the path conventions and the name hints of collection_index, copied from it unchanged (tests/pack-triage-records.test.ts holds them equal)
DRIVE_BARE = re.compile(r"^[A-Za-z]$")
DRIVE_MARKED = re.compile(r"^([A-Za-z])(?:\$|:|%3[Aa])$")
# Greedy, so the split is at the LAST underscore: report.txt_Zone.Identifier has to give "report.txt" and
# "Zone.Identifier", not "report" and the rest.
STREAM_HINT = re.compile(r"^(.+)_(\$?[A-Za-z][\w.$-]{1,40})$")
KNOWN_STREAMS = {"zone.identifier", "summaryinformation", "documentsummaryinformation", "favicon", "encryptable",
                 "afp_afpinfo", "afp_resource", "com.dropbox.attributes", "com.apple.quarantine", "ads", "$data"}
PLAIN_SUFFIXES = {"plist", "json", "db", "txt", "log", "xml", "png", "jpg", "jpeg", "gif", "html", "htm", "css", "js", "sqlite", "dat", "bin", "md"}   # a "stream" that ends like a file
RESERVED = {"CON", "PRN", "AUX", "NUL"} | {"COM%d" % i for i in range(1, 10)} | {"LPT%d" % i for i in range(1, 10)}
# First directory names of a Unix-like root: a path that starts with one is read as rooted at /.
UNIX_TOP = {"etc", "var", "home", "usr", "opt", "tmp", "bin", "sbin", "lib", "lib64", "root", "srv", "mnt", "run", "boot", "dev",
            "proc", "sys", "media", "private", "Library", "Users", "Applications", "System", "Volumes"}
# What a name says about a file that holds, or is, a credential store. A name hint and nothing more.
CREDENTIAL_NAMES = {
    "shadow": "a password verifier file", "gshadow": "a password verifier file", "shadow-": "a password verifier file",
    "gshadow-": "a password verifier file", "master.passwd": "a password verifier file", "spwd.db": "a password verifier file",
    "pwd.db": "a password verifier file", ".htpasswd": "a password verifier file", "sam": "a Windows account database hive",
    "security": "a Windows security hive", "ntds.dit": "a directory database with password verifiers", "wallet.dat": "a wallet file",
    "keychain-2.db": "a keychain", "keychain-2.db-wal": "a keychain", "keychain-2.db-shm": "a keychain",
    "krb5.keytab": "a Kerberos key table", ".env": "an environment file that often holds secrets",
    "login data": "a browser saved-credential database", "login data for account": "a browser saved-credential database",
    "logins.json": "a browser saved-credential file", "key3.db": "a browser key database", "key4.db": "a browser key database",
    "cert9.db": "a browser certificate and key database", "signons.sqlite": "a browser saved-credential database",
    "cookies": "a browser cookie store", "cookies.sqlite": "a browser cookie store", "local state": "a browser key-wrapping file",
    "web data": "a browser form and card store", ".pgpass": "a saved-credential file", ".netrc": "a saved-credential file",
    ".git-credentials": "a saved-credential file", ".npmrc": "a saved-credential file", ".pypirc": "a saved-credential file",
    ".dockercfg": "a saved-credential file", "id_rsa.bak": "a private key file",
    "terraform.tfstate": "infrastructure state that holds secrets", "terraform.tfstate.backup": "infrastructure state that holds secrets",
    "credentials.xml": "a saved-credential file", "credentials": "a saved-credential file", "credentials.db": "a saved-credential database",
    "access_tokens.db": "a cloud access-token database", "accesstokens.json": "a cloud access-token file", "msal_token_cache.json": "a token cache",
    "token_cache.json": "a token cache", "wp-config.php": "a web application configuration that holds database credentials",
    "secrets.yaml": "a secrets file", "secrets.yml": "a secrets file", "secrets.json": "a secrets file", "tokens.json": "a token file", "vault.json": "a vault file",
    ".my.cnf": "a database client file that can hold a password", ".s3cfg": "a saved-credential file", ".boto": "a saved-credential file", "htpasswd": "a password verifier file",
    "lsass.dmp": "a process dump of the credential-holding LSASS process", "kubeconfig": "a saved-credential file", ".vault-token": "a token file",
}
CREDENTIAL_SUFFIXES = {".p8": "a private key file", ".jceks": "a Java key store", ".pkcs12": "a key and certificate store", ".asc": "an armoured key or message file",
                       ".ovpn": "a VPN profile that can hold keys", ".rdp": "a remote-desktop file that can hold a saved credential", ".tfvars": "variables that can hold secrets",
                       ".ppk": "a private key file", ".p12": "a key and certificate store", ".pfx": "a key and certificate store",
                       ".pem": "a key or certificate file", ".key": "a key file", ".keytab": "a Kerberos key table", ".kdb": "a password database",
                       ".kdbx": "a password database", ".jks": "a Java key store", ".keystore": "a Java key store", ".gpg": "an encrypted file",
                       ".keychain": "a keychain", ".keychain-db": "a keychain", ".bek": "a BitLocker key file", ".kirbi": "a Kerberos ticket",
                       ".ccache": "a Kerberos credential cache"}
CREDENTIAL_DIRECTORIES = {".gnupg": "a GnuPG directory", ".aws": "an AWS credentials directory", ".azure": "an Azure credentials directory",
                          "gcloud": "a Google Cloud credentials directory", ".kube": "a Kubernetes configuration directory", ".docker": "a Docker configuration directory",
                          ".vnc": "a VNC configuration directory",  "protect": "a DPAPI master-key store",
                          "credentials": "a Windows credential store", "vault": "a Windows vault", "private-keys-v1.d": "a GnuPG private key store"}


def credential_hint(name, parents):
    """What a file's name (and its directories) say it is, or None. `parents` are the directory names above it, lower case."""
    low = name.lower()
    found = CREDENTIAL_NAMES.get(low)
    if found is None and low.startswith(("sam.log", "security.log", "software.log", "system.log")):
        found = "a hive transaction log (it can hold credential material)"
    if found is None and low.startswith("id_") and not low.endswith(".pub"):
        found = "a private key file"
    if found is None and low.startswith("ssh_host_") and low.endswith("_key"):
        found = "a host private key file"
    if found is None and low == "config.json" and ".docker" in parents:
        found = "a saved-credential file"
    if found is None and low == "config" and ".kube" in parents:
        found = "a saved-credential file"
    if found is None and low.startswith("shadow"):
        found = "a password verifier file"
    if found is None and "recovery" in low and ("bitlocker" in low or "key" in low) and low.endswith((".txt", ".bek", ".csv")):
        found = "a BitLocker recovery key file"
    if found is None:
        found = CREDENTIAL_SUFFIXES.get(os.path.splitext(low)[1])
    if found is None and low != "known_hosts" and low != "config" and not low.endswith(".pub") and ".ssh" in parents:
        found = "an SSH directory file"
    if found is None:
        for directory in parents:
            if directory in CREDENTIAL_DIRECTORIES:
                found = CREDENTIAL_DIRECTORIES[directory]
                break
    return found


def source_path_hypothesis(rel):
    """What a convention would make of a path in the collection: a hypothesis with its method, its confidence, what it could
    not explain and the other readings. It is never an observation; only a collector's own mapping observes a source path."""
    parts = [p for p in rel.split(os.sep) if p not in ("", ".")]
    first = parts[0] if parts else ""
    rest = parts[1:]
    alternatives, unresolved = [], []
    marked = DRIVE_MARKED.match(first)
    uac_at = parts.index("[root]") if "[root]" in parts[:-1] else -1
    if len(parts) < 2:
        path = "/".join(parts)
        method, confidence = "none: a file at the top of the collection has no directory to read a convention from", "none"
    elif uac_at >= 0:
        path = "/" + "/".join(parts[uac_at + 1:])
        unresolved = parts[:uac_at]
        method = "UAC's [root] directory holds the collected files below /" + (" (the directories above it are unresolved)" if uac_at else "")
        confidence = "medium" if uac_at == 0 else "low"
    elif marked or DRIVE_BARE.match(first):
        letter = (marked.group(1) if marked else first).upper()
        path = letter + ":\\" + "\\".join(rest)
        if marked:
            method, confidence = "the first directory is spelled like a drive (%s)" % first, "medium"
        else:
            method, confidence = "the first directory is a single letter, read as a drive letter", "low"
        alternatives.append({"path": "/" + "/".join(parts), "if": "the first directory is an ordinary directory that happens to be named %s" % first})
    elif first == "uploads":
        path = "/".join(parts)
        method, confidence = "none: the delivered path, unchanged (uploads/<accessor>/<path> needs the collector's own index to read)", "none"
        unresolved = parts[:3] if len(parts) > 2 else parts[:1]
        if len(parts) > 3 and DRIVE_MARKED.match(parts[2]):
            alternatives.append({"path": DRIVE_MARKED.match(parts[2]).group(1).upper() + ":\\" + "\\".join(parts[3:]),
                                 "if": "uploads/<accessor>/<drive> is Velociraptor's layout (check the collection's own records)"})
    elif first in UNIX_TOP:
        path = "/" + "/".join(parts)
        method, confidence = "the first directory is a top-level directory of a Unix-like file system, read as rooted at /", "low"
        if first == "root":
            unresolved = ["root"]
            alternatives.append({"path": "/" + "/".join(rest), "if": "root is a collector's wrapper directory and not the /root home directory"})
    else:
        path = "/".join(parts)
        method, confidence = "none: the delivered path, unchanged; no convention recognised", "none"
    return {"path": path, "method": method, "confidence": confidence, "unresolved_components": unresolved, "alternatives": alternatives}




def split_stream(path):
    """(base, stream) for a source path with NTFS stream syntax (C:\\dir\\file:name), else (path, None). A drive's own colon is not one."""
    if not isinstance(path, str):
        return path, None
    start = 2 if re.match(r"^[A-Za-z]:[\\/]", path) else 0
    last = max(path.rfind("\\"), path.rfind("/"))
    colon = path.find(":", max(start, last + 1))
    if colon <= 0 or colon == len(path) - 1:
        return path, None
    return path[:colon], path[colon + 1:]


def component_notes(rel):
    """What in a delivered path a reader could misread: components that are not UTF-8 (escaped here as surrogates), and components
    that carry percent-escapes (a collector's way of writing ':' and the like)."""
    not_utf8, escaped = [], []
    for part in rel.replace(os.sep, "/").split("/"):
        if undecodable(part):
            not_utf8.append(part)
        elif re.search(r"%[0-9A-Fa-f]{2}", part):
            escaped.append(part)
    return not_utf8, escaped


def percent_decode(part):
    return re.sub(r"%([0-9A-Fa-f]{2})", lambda m: chr(int(m.group(1), 16)) if int(m.group(1), 16) < 0x80 else m.group(0), part)


def source_path_shown(rec):
    """The source path a record claims, normalised only so that two claims of one file compare equal: '/' for either separator, no
    trailing stream, the case kept (the caller folds it when it compares)."""
    claim = rec.get("source_path_claim")
    if not isinstance(claim, str):
        return None
    base, _stream = split_stream(claim)
    return base.replace("\\", "/")


def path_hint(*paths):
    """The first credential-store hint any of the given paths carries (by the name and the directories above it), or None."""
    for path in paths:
        if isinstance(path, str) and path:
            parts = [p for p in re.split(r"[\\/]+", path) if p]
            if parts:
                found = credential_hint(parts[-1], [p.lower() for p in parts[:-1]])
                if found:
                    return found
    return None


def withhold_digest(value, where):
    """A digest of a file that is a credential store never leaves in an answer or a table: it goes to the values file (a job run with
    secret_output and write_values) and what is printed names its length and a finding id. Returns the marker."""
    WITHHELD["count"] += 1
    fid = "W%06d" % WITHHELD["count"]
    if VALUES[0] is not None:
        VALUES[0].add(fid, {"where": where}, value)
    return "<digest of a credential store withheld, %d characters, %s>" % (len(value), fid)


def guard_digests(rec):
    """For a record that names a credential store, the collector's own digests are withheld from the record (the comparison still
    runs on the real ones, in the caller)."""
    hint = path_hint(rec.get("source_path_claim"), rec.get("delivered_path_claim"))
    if hint and rec.get("hash_claims"):
        where = "record %s of %s" % ((rec.get("locator") or {}).get("row") or (rec.get("locator") or {}).get("line"), rec.get("log"))
        rec["hash_claims"] = {algorithm: withhold_digest(value, where) for algorithm, value in rec["hash_claims"].items()}
        rec["flags"] = list(rec.get("flags") or []) + ["digest_withheld_credential_store"]
        rec["credential_store_hint"] = hint
    return rec

# ---- END RECORDS BLOCK -----------------------------------------------------------------------------------------------


RECIPE_ID = "collection-intake"
NESTED_SUFFIXES = (".zip", ".tar", ".tgz", ".tar.gz", ".tbz2", ".tar.bz2", ".txz", ".tar.xz", ".7z", ".rar", ".gz", ".bz2", ".xz", ".zst", ".ad1", ".e01", ".ex01")
STATUS_ORDER = ("matched", "mismatch", "missing", "unverifiable", "ambiguous", "read_failed")
KEPT_DIRS = []


class Stopped(Exception):
    pass


def limits():
    try:
        spec = json.load(open(os.path.join(HERE, "recipe.json")))
        lim = spec.get("limits", {})
    except Exception:
        lim = {}
    return int(os.environ.get("RECIPE_SECONDS") or lim.get("seconds") or 7200)


def target_of(arg):
    text = open(arg, encoding="utf-8").read() if os.path.isfile(arg) else arg
    t = json.loads(text)
    paths = t.get("paths") or []
    if not paths or not isinstance(paths[0], str):
        raise SystemExit(json.dumps({"ok": False, "error": "the target names no path"}))
    return t, paths[0]


def sniff(path):
    """(format, why): zip, or tar (plain, gzip, bzip2 or xz), judged from the bytes; 7z is named and not read."""
    try:
        with open(path, "rb") as fh:
            head = fh.read(512)
    except OSError as exc:
        return None, "the file could not be read (%s)" % describe(exc)
    if head[:4] in (b"PK\x03\x04", b"PK\x05\x06"):
        return "zip", None
    if head[:6] == b"7z\xbc\xaf\x27\x1c":
        return None, "a 7z archive: this recipe reads zip and tar; list it with archive-members and extract it with archive_extract"
    if head[257:262] == b"ustar" or head[:2] == b"\x1f\x8b" or head[:3] == b"BZh" or head[:6] == b"\xfd7zXZ\x00":
        try:
            with tarfile.open(path, mode="r|*") as tf:
                tf.next()
        except (tarfile.TarError, OSError, EOFError) as exc:
            return None, "not a tar archive (%s)" % describe(exc)
        return "tar", None
    return None, "neither a zip nor a tar by its first bytes"


def iterate(path, fmt):
    """(name, kind, header size, opener) for each member in archive order; kind f (regular file), l (link), s (special), d (directory).
    The opener is valid only while the member is the current one."""
    if fmt == "zip":
        with zipfile.ZipFile(path) as zf:
            for info in zf.infolist():
                mode = (info.external_attr >> 16) & 0o170000
                kind = "d" if info.is_dir() else "l" if mode == 0o120000 else "s" if mode in (0o020000, 0o060000, 0o010000, 0o140000) else "f"
                yield info.filename, kind, info.file_size, (lambda i=info: zf.open(i))
    else:
        with tarfile.open(path, mode="r|*") as tf:
            for member in tf:
                kind = "d" if member.isdir() else "f" if member.isreg() else "l" if (member.issym() or member.islnk()) else "s"
                yield member.name, kind, member.size, (lambda m=member: tf.extractfile(m))


def marker_name(rel):
    name = name_of(rel)
    low = name.lower()
    if inside_collected_data(rel):
        return False
    return (low.endswith(("_copylog.csv", "_skiplog.csv", "_consolelog.txt")) or name in ("uac.log", "uploads.json", "collection_context.json", "log.json")
            or low in HASH_LIST_NAMES or (name.endswith(".json") and name_of(parent_of(rel)) == "results"))


def esc(text):
    """A name with every character outside printable ASCII, and the backslash, written as \\uXXXX (a lone surrogate from a name that was not UTF-8 too)."""
    return "".join(c if " " <= c <= "~" and c != "\\" else "\\u%04x" % ord(c) if ord(c) < 0x10000 else "\\U%08x" % ord(c) for c in text)


def member_rel(name):
    """A member's name as the census keys it: separators collapsed, no leading './' or '/'."""
    return "/".join(p for p in name.split("/") if p not in ("", "."))


class ArchiveSource:
    """The collector's records from the archive, kept as temporary files: each opened afresh, so a record read twice is read twice."""
    kind = "archive"

    def __init__(self, kept):
        self.kept = kept

    def open_binary(self, rel):
        path = self.kept.get(rel)
        if path is None:
            raise OSError(2, "the member was not kept: it is not a record this recipe reads, or it was over %d bytes" % MAX_KEPT_BYTES)
        return open(path, "rb")

    def head(self, rel, count=4096):
        with self.open_binary(rel) as fh:
            return fh.read(count)


def pass_one(path, fmt, out_dir, census, inventory, digests, kept, state):
    """One pass over the members in order: inventory, digests, and the collector's records kept for parsing. Nothing is extracted."""
    tmp = tempfile.mkdtemp(dir=out_dir, prefix=".intake-")
    KEPT_DIRS.append(tmp)
    state["tmp"] = tmp
    n = 0
    for name, kind, header_size, opener in iterate(path, fmt):
        if n >= MAX_MEMBERS:
            state["limit"] = "the member cap of %d" % MAX_MEMBERS
            break
        if out_of_time():
            state["limit"] = "the time limit"
            break
        n += 1
        rel = member_rel(name)
        size, digest_row = header_size, None
        if kind == "f":
            hashers = (hashlib.sha256(), hashlib.sha1(), hashlib.md5())
            keep = marker_name(rel)
            dest = None
            total = 0
            try:
                fh = opener()
                if fh is None:
                    raise OSError(22, "the member cannot be read")
                with fh:
                    if keep:
                        dest = open(os.path.join(tmp, "k%d" % n), "wb")
                    while True:
                        block = fh.read(1 << 20)
                        if not block:
                            break
                        total += len(block)
                        for h in hashers:
                            h.update(block)
                        if dest is not None:
                            if total > MAX_KEPT_BYTES:
                                dest.close()
                                os.unlink(dest.name)
                                dest = None
                                state["too_large"].append(rel)
                            else:
                                dest.write(block)
                        if out_of_time():
                            raise Stopped()
            except Stopped:
                if dest is not None:
                    dest.close()
                state["limit"] = "the time limit (member %d was being read)" % n
                inventory.append((n, kind, header_size, None, rel, "the time limit ended the read of this member"))
                census.add(rel, header_size, "f")
                break
            except (OSError, RuntimeError, EOFError, zipfile.BadZipFile, tarfile.TarError, ValueError, NotImplementedError) as exc:
                if dest is not None:
                    dest.close()
                state["unreadable"].append({"n": n, "name": rel, "error": describe(exc)})
                inventory.append((n, kind, header_size, None, rel, "unreadable: " + describe(exc)))
                census.add(rel, header_size, "f")
                continue
            if dest is not None:
                dest.close()
                kept[rel] = dest.name
            size = total
            digest_row = {"sha256": hashers[0].hexdigest(), "sha1": hashers[1].hexdigest(), "md5": hashers[2].hexdigest()}
            digests.setdefault(rel, []).append(digest_row)
            census.add(rel, size, "f")
            if rel.lower().endswith(NESTED_SUFFIXES):
                state["nested"].append({"n": n, "name": rel, "bytes": size})
            hint = path_hint(rel)
            inventory.append((n, kind, size, "(withheld: %s)" % hint if hint else digest_row["sha256"], rel, ""))
        elif kind in ("l", "s"):
            census.add(rel, 0, kind)
            inventory.append((n, kind, header_size, None, rel, "a link or a special file: recorded, not followed"))
        else:
            state["directories"] += 1
    state["members"] = n


class IntakeSink(Sink):
    """Writes each record, and checks each delivery claim against the members' size and digests."""

    def __init__(self, census, digests, records_fh, verification_fh):
        super().__init__()
        self.census, self.digests = census, digests
        self.records_fh, self.verification_fh = records_fh, verification_fh
        self.by_status = {}
        self.not_checked = 0
        self.by_kind = {}

    def record(self, rec):
        self.count += 1
        rec["n"] = self.count
        original = dict(rec.get("hash_claims") or {})
        guard_digests(rec)
        self.by_kind[rec["kind"]] = self.by_kind.get(rec["kind"], 0) + 1
        self.records_fh.write(json.dumps(rec, default=str) + "\n")
        if rec["outcome"] in ("skipped", "upload_error", "error", "warning") or rec["kind"] in ("log_event", "unrecognised_row"):
            self.not_checked += 1
            return
        res = resolve(self.census, rec)
        if res["status"] == "no_claim":
            self.not_checked += 1
            return
        row = {"n": rec["n"], "status": None, "collector": rec["collector"], "run": rec["run"], "kind": rec["kind"], "locator": rec.get("locator"),
               "source_path_claim": rec.get("source_path_claim"), "delivered_path_claim": rec.get("delivered_path_claim"), "member": res.get("rel"),
               "matched_by": res.get("matched_by"), "path": {"result": res["status"]}, "size": {"result": "not_claimed"}, "hash": {"result": "not_claimed"}}
        if res.get("reason"):
            row["path"]["reason"] = res["reason"]
        status = None
        if res["status"] == "ambiguous":
            status = "ambiguous"
        elif res["status"] == "unknown":
            status = "unverifiable"
            row["path"]["reason"] = "the member list is not complete: absence is not decided"
        elif res["status"] == "missing":
            status = "unverifiable" if rec["kind"] == "hash_claim" else "missing"
            if rec["kind"] == "hash_claim":
                row["path"]["reason"] = "the list names a file of the source host, and the archive holds no collected copy of it"
        elif res["status"] == "not_regular":
            status = "unverifiable"
        if status is None:
            rel = res["rel"]
            claimed_size = rec.get("size_claim")
            if claimed_size is not None:
                row["size"] = {"result": "match" if claimed_size == res.get("size") else "mismatch", "claimed": claimed_size, "measured": res.get("size")}
            claims = original
            sparse = any(f in (rec.get("flags") or []) for f in ("stored_smaller_than_file", "sparse_index"))
            held = self.digests.get(rel) or []
            hint = path_hint(rel, rec.get("source_path_claim"))
            if claims:
                row["hash"] = {"result": "not_attempted", "claimed": dict(rec.get("hash_claims") or {})}
                if hint:
                    row["hash"]["credential_store_hint"] = hint
                if sparse:
                    row["hash"] = {**row["hash"], "result": "unverifiable", "reason": "the upload is smaller than the file (a sparse or partial upload): its stored bytes are another sequence"}
                elif not held:
                    row["hash"]["reason"] = "the member was not read to the end (see coverage)"
                else:
                    compared = {a: held[0].get(a) == v for a, v in claims.items() if a in held[0]}
                    row["hash"]["result"] = "unverifiable" if not compared else ("match" if all(compared.values()) else "mismatch")
                    row["hash"]["measured_sha256"] = "(withheld: %s)" % hint if hint else held[0]["sha256"]
            if row["size"]["result"] == "mismatch" or row["hash"]["result"] == "mismatch":
                status = "mismatch"
            elif row["hash"]["result"] in ("not_attempted", "unverifiable") and claims:
                status = "unverifiable"
            elif row["size"]["result"] == "match" or row["hash"]["result"] == "match":
                status = "matched"
            else:
                status = "unverifiable"
                row["path"]["note"] = "the record claims neither a size nor a digest: only the existence of the member is established"
        row["status"] = status
        self.by_status[status] = self.by_status.get(status, 0) + 1
        self.verification_fh.write(json.dumps(row, default=str) + "\n")

    def problem(self, row):
        pass


def write_json(path, value):
    tmp = path + ".part"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(value, fh, indent=2, default=str)
    os.replace(tmp, path)


def cleanup():
    for d in KEPT_DIRS:
        try:
            for name in os.listdir(d):
                try:
                    os.unlink(os.path.join(d, name))
                except OSError:
                    pass
            os.rmdir(d)
        except OSError:
            pass


def on_signal(signum, frame):
    cleanup()
    print(json.dumps({"ok": False, "status": "failed", "error": "the recipe was stopped by signal %d; the receipt written first says it did not finish" % signum}))
    raise SystemExit(128 + signum)


def detect(path):
    """(exit code, answer). Applies when a member is named like a collector's record; the listing is bounded and a bound that is hit is
    'could not tell', never 'does not apply'."""
    fmt, why = sniff(path)
    if fmt is None:
        return (1 if "neither a zip nor a tar" in (why or "") or "not a tar" in (why or "") else 2), {"applies": False, "why": why}
    census = Census()
    deadline = time.monotonic() + float(os.environ.get("COLLECTION_INTAKE_DETECT_SECONDS", "120"))
    stopped = None
    n = 0
    try:
        for name, kind, _size, _opener in iterate(path, fmt):
            n += 1
            if kind == "f":
                census.add(member_rel(name), 0, "f")
            if n >= MAX_MEMBERS:
                stopped = "the member cap of %d" % MAX_MEMBERS
                break
            if (n & 255) == 0 and time.monotonic() > deadline:
                stopped = "the detect time limit"
                break
    except (tarfile.TarError, zipfile.BadZipFile, OSError, EOFError, ValueError) as exc:
        stopped = "the listing failed (%s)" % describe(exc)
    markers = [rel for rel, _s, k in census.entries() if k == "f" and marker_name(rel)]
    if markers:
        return 0, {"applies": True, "format": fmt, "why": "%d member(s) are named like a collector's record (first: %s)" % (len(markers), esc(markers[0]))}
    if stopped:
        return 2, {"applies": False, "why": "no collector record among the %d members listed, and the listing stopped (%s): could not tell" % (n, stopped)}
    return 1, {"applies": False, "why": "no member of the %d is named like a collector's record" % n}


def run(path, out_dir, probe=False):
    seconds = limits()
    DEADLINE[0] = time.monotonic() + seconds * 0.9
    os.makedirs(out_dir, exist_ok=True)
    cov_path = os.path.join(out_dir, "coverage.json")
    cov = {"recipe": RECIPE_ID, "target": path, "status": "partial", "status_basis": "started; the pass over the members was not finished (the run stopped before its end)",
           "covered": "the member list, a digest of every member, the collector's records and their agreement with the members",
           "not_covered": ("member contents beyond the collector's records; archives inside the archive; whether the archive is authentic or complete as acquired; "
                           "what the collector was asked to take; the original path of a member (collection_path_map); the coverage of a question (collection_coverage)"),
           "limits_hit": [], "errors": []}
    write_json(cov_path, cov)
    fmt, why = sniff(path)
    if fmt is None:
        cov.update(status="failed", status_basis=why)
        write_json(cov_path, cov)
        print(json.dumps({"ok": False, "status": "failed", "error": why}))
        return 2
    signal.signal(signal.SIGTERM, on_signal)
    signal.signal(signal.SIGINT, on_signal)
    if hasattr(signal, "SIGHUP"):
        signal.signal(signal.SIGHUP, on_signal)
    census, inventory, digests, kept = Census(), [], {}, {}
    state = {"limit": None, "too_large": [], "unreadable": [], "nested": [], "directories": 0, "members": 0, "tmp": None}
    try:
        try:
            pass_one(path, fmt, out_dir, census, inventory, digests, kept, state)
        except (tarfile.TarError, zipfile.BadZipFile, OSError, EOFError, ValueError, RuntimeError) as exc:
            cov["errors"].append("the pass over the members stopped: %s" % describe(exc))
            census.complete = False
        if state["limit"]:
            cov["limits_hit"].append(state["limit"])
            census.complete = False
        found = discover(census)
        with open(os.path.join(out_dir, "records.jsonl"), "w", encoding="utf-8") as records_fh, \
                open(os.path.join(out_dir, "verification.jsonl"), "w", encoding="utf-8") as verification_fh:
            sink = IntakeSink(census, digests, records_fh, verification_fh)
            sources = read_collection(ArchiveSource(kept), found, sink)
        with open(os.path.join(out_dir, "inventory.tsv"), "w", encoding="utf-8") as fh:
            fh.write("n\tkind\tsize\tsha256\tname\tnote\n")
            for n, kind, size, sha, name, note_text in inventory:
                fh.write("%d\t%s\t%s\t%s\t%s\t%s\n" % (n, kind, size, sha or "", esc(name), note_text))
        units = {}
        for s in sources:
            units.setdefault("%s|%s|%s" % (s["collector"], s["run"], s.get("directory", ".")), []).append(s)
        write_json(os.path.join(out_dir, "units.json"), {
            "units": [{"collector": k.split("|")[0], "run": k.split("|")[1], "directory": k.split("|")[2], "collector_version": "unknown",
                       "sources": [{key: s[key] for key in ("log", "adapter", "status", "reason", "rows", "records", "malformed_rows") if key in s} for s in group]}
                      for k, group in units.items()],
            "unsupported": [{"collector": "CyLR", "why": ADAPTERS["cylr"]["schema"]}],
            "records_inside_collected_data": [esc(x) for x in found["inside_collected"][:100]]})
        problems = []
        problems += cov["errors"]
        if state["limit"]:
            problems.append("the pass stopped at %s" % state["limit"])
        if state["unreadable"]:
            problems.append("%d member(s) could not be read" % len(state["unreadable"]))
        if state["too_large"]:
            problems.append("%d collector record(s) were over %d bytes and were not parsed" % (len(state["too_large"]), MAX_KEPT_BYTES))
        problems += ["%s is %s" % (esc(s["log"]), s["status"]) for s in sources if s["status"] != "parsed"]
        if not sources:
            problems.append("no recognised collector record was read")
        status = "complete" if not problems else ("partial" if state["members"] else "failed")
        cov.update(status=status, status_basis=("every member was read and hashed and every recognised record was read whole" if not problems else "; ".join(problems[:10])),
                   format=fmt, members=state["members"], files=census.files, directories=state["directories"],
                   records=sink.count, records_by_kind=dict(sorted(sink.by_kind.items())), verification=dict(sorted(sink.by_status.items())),
                   records_not_checked=sink.not_checked, nested_archives=state["nested"][:1000], nested_archives_total=len(state["nested"]),
                   nested_archives_note=("named, not opened: extract one with archive_extract (from_index is its n in inventory.tsv) and run this recipe or the "
                                         "collection tools on the result"),
                   members_unreadable=state["unreadable"][:100], members_unreadable_total=len(state["unreadable"]),
                   outputs={"inventory": "inventory.tsv", "records": "records.jsonl", "verification": "verification.jsonl", "units": "units.json"})
        write_json(cov_path, cov)
        with open(os.path.join(out_dir, "index.tsv"), "w", encoding="utf-8") as fh:
            fh.write("inventory.tsv\tmembers (%d): n, kind, size, sha256, name, note\n" % state["members"])
            fh.write("records.jsonl\tthe collector's records, one per row or line, with the locator of the raw row\n")
            fh.write("verification.jsonl\tone row per delivery claim: path, size and digest checked apart, and the status they add up to\n")
            fh.write("units.json\tthe collectors' runs and containers recognised, with the status of each source\n")
        print(json.dumps({"ok": status in ("complete", "partial"), "status": status, "members": state["members"], "records": sink.count,
                          "verification": dict(sorted(sink.by_status.items()))}))
        return 0 if status in ("complete", "partial") else 2
    finally:
        cleanup()


def main(argv):
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("verb", choices=("detect", "run"))
    parser.add_argument("--target", required=True)
    parser.add_argument("--out")
    parser.add_argument("--probe-out")
    try:
        args = parser.parse_args(argv[1:])
    except SystemExit:
        print(json.dumps({"ok": False, "error": "usage: run.py detect --target T [--probe-out DIR] | run --target T --out DIR"}))
        return 2
    _t, path = target_of(args.target)
    if args.verb == "detect":
        code, answer = detect(path)
        print(json.dumps(answer))
        return code
    if not args.out:
        print(json.dumps({"ok": False, "error": "run needs --out DIR"}))
        return 2
    return run(path, args.out)


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv))
    except SystemExit:
        raise
    except BaseException as exc:
        cleanup()
        print(json.dumps({"ok": False, "status": "failed", "error": "the recipe stopped on an unexpected error (%s)" % type(exc).__name__, "detail": str(exc)}))
        sys.exit(2)
