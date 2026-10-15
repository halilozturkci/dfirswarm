#!/usr/bin/env python3
"""The application and file inventory of an Amcache.hve registry hive.

What this is: an inventory of binaries the system recorded, with their path, the
hash the inventory holds, the publisher and the dates it keeps. Presence in it is
not proof that a program ran, and absence from it is not proof that one did not:
which entries exist, and when, depends on the Windows build, the inventory task
and the hive's state. The key layout differs between Windows versions and BOTH are
read when both are present, each row naming its layout:

  Root\\File\\<volume>\\<id>                  the older layout; values are numbered
  Root\\InventoryApplicationFile\\<id>        the newer layout; values are named

The numbered values are named by the published research regipy's own Amcache plugin
follows (`5` file version, `c` file description, `f` the PE linker timestamp, `11`,
`12` and `17` FILETIMEs, `15` the full path, `100` the program id, `101` the SHA-1);
that mapping is not Microsoft documentation. The linker timestamp is a 32-bit Unix-epoch
value copied from the PE header, not a FILETIME, and is converted as one; the raw value is
kept beside it. A hash is returned as stored (`sha1_raw`, with the four leading zeros the
value carries) and stripped only where it has that shape. What range of the file the
inventory hashed is not established here. The hive is read as it is on disk: a hive
whose sequence numbers differ is reported dirty, and its transaction logs are not replayed.
"""
import datetime
import json
import os
import re
import stat
import sys
from pathlib import Path

# Lossless paging (the same in every library tool that pages): the page an
# agent reads stays small, and when there are more rows the whole result is
# written as JSON Lines under work/<agent>/tool-output and named.
import hashlib
import json
import os
import re
import tempfile
from pathlib import Path


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
# <stem>-<n><suffix>. The name is taken first, with an exclusive create, so a result written at the same moment cannot be replaced either.
def same_bytes(a, b):
    """Whether two files hold the same bytes (read in blocks, never whole)."""
    try:
        if os.path.getsize(a) != os.path.getsize(b):
            return False
        with open(a, "rb") as fa, open(b, "rb") as fb:
            while True:
                x, y = fa.read(1 << 20), fb.read(1 << 20)
                if x != y:
                    return False
                if not x:
                    return True
    except OSError:
        return False


def place_without_replacing(tmp, path):
    """Move the finished `tmp` to `path` and never replace what is there. The name is taken first, with an exclusive create, so a
    result written at the same moment cannot be replaced either. Returns the path that holds it."""
    for n in range(1, 1000):
        candidate = path if n == 1 else path.with_name("%s-%d%s" % (path.stem, n, path.suffix))
        try:
            fd = os.open(str(candidate), os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        except FileExistsError:
            if not os.path.islink(candidate) and same_bytes(tmp, candidate):
                os.unlink(tmp)
                return candidate
            continue
        os.close(fd)
        os.replace(tmp, candidate)             # only replaces the empty file this call just made
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


# BEGIN SHARED STOP
# The same text is in regkv, shellbags and amcache_apps (held equal by a windows-forensics test). SIGTERM, SIGINT and SIGHUP end the tool with JSON (status
# interrupted, exit 128 + the signal) and remove the temporary file a page was writing; the tool's own clock (set_deadline) is below the manifest's.
import signal
import time

STOP = {"last_word": None, "deadline": None}


def set_deadline(seconds):
    STOP["deadline"] = time.monotonic() + seconds


def out_of_time():
    return STOP["deadline"] is not None and time.monotonic() > STOP["deadline"]


def _on_signal(signum, _frame):
    for page in list(PAGES):
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
    os._exit(128 + signum)


def install_signal_handlers(last_word=None):
    STOP["last_word"] = last_word
    for signum in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(signum, _on_signal)


def interrupted_answer(signum, **extra):
    print(json.dumps({"error": "stopped by signal %d before the answer was complete" % signum, "status": "interrupted",
                      "status_basis": "the tool was stopped by signal %d; nothing it had read is an answer" % signum,
                      "signal": signum, **extra}), flush=True)
# END SHARED STOP


# BEGIN SHARED HIVE BOUNDS
# The same text is in regkv, shellbags and amcache_apps (a windows-forensics test holds the copies equal).
# A hive of N bytes holds at most N // 76 key cells (an nk cell is at least 76 bytes) and N // 20 value cells (a vk cell is at least 20), however
# many elements an index claims: regipy follows a subkey index (ri) element by element, so one list repeated by an index is read as many times as
# it is repeated (a 61 KB hive listed a million keys and took 1.2 GB). Every list of subkeys and values is read through these bounds, and what is
# past one is said, never followed.
import itertools
import logging
import warnings

KEY_CELL_BYTES = 76
VALUE_CELL_BYTES = 20


class LibraryLog(logging.Handler):
    """regipy reports what it cannot parse through the logging module, and its text carries bytes of the value or the name it failed on
    (for a text value that is neither UTF-16 nor UTF-8: the byte and its position). The text is not printed anywhere: it is counted."""
    messages = 0
    errors = 0

    def emit(self, record):
        LibraryLog.messages += 1
        if record.levelno >= logging.ERROR:
            LibraryLog.errors += 1


def withhold_library_output():
    logging.root.handlers[:] = [LibraryLog()]
    warnings.simplefilter("ignore")


class HiveBounds:
    def __init__(self, hive_path, size=None):
        size = os.path.getsize(hive_path) if size is None else size
        self.hive_bytes = size
        self.key_cells = max(size // KEY_CELL_BYTES, 1)
        self.value_cells = max(size // VALUE_CELL_BYTES, 1)
        self.keys_read = 0                      # subkey elements read over the whole walk
        self.data_read = 0                      # bytes of value data read over the whole walk
        self.repeats = 0                        # elements that named a key already named in the same list

    def subkeys(self, node, where, problems):
        """The distinct subkeys of `node`, at most the keys the hive can still hold; what is past that, or repeated, is a problem line."""
        room = max(self.key_cells - self.keys_read, 0)
        raw = list(itertools.islice(node.iter_subkeys() or [], room + 1))
        if len(raw) > room:
            raw = raw[:room]
            problems.append({"where": where, "what": "subkeys",
                             "error": "its subkey list yields more keys than a %d-byte hive can hold (%d keys at most, %d already read in this walk): "
                                      "an index that repeats a list; the elements past that are not read" % (self.hive_bytes, self.key_cells, self.keys_read)})
        self.keys_read += len(raw)
        seen, distinct, repeated = set(), [], 0
        for sub in raw:
            header = getattr(sub, "header", None)
            identity = (str(getattr(sub, "name", "")).lower(), getattr(header, "last_modified", None),
                        getattr(header, "subkeys_list_offset", None), getattr(header, "values_list_offset", None))
            if identity in seen:
                repeated += 1
                continue
            seen.add(identity)
            distinct.append(sub)
        if repeated:
            self.repeats += repeated
            problems.append({"where": where, "what": "subkeys",
                             "error": "its subkey list names %d key(s) more than once; each is listed once" % repeated})
        return distinct

    def values(self, node, where, problems, **kwargs):
        """At most the values the hive can hold, as a list, and at most the data it can hold over the whole walk (a value list that names one big
        record again and again reads that record every time); a key that lists more is a problem line."""
        raw = []
        for v in itertools.islice(node.iter_values(**kwargs), self.value_cells + 1):
            if len(raw) >= self.value_cells:
                problems.append({"where": where, "what": "values",
                                 "error": "its value list yields more values than a %d-byte hive can hold (%d at most): the elements past that are not read"
                                          % (self.hive_bytes, self.value_cells)})
                break
            data = getattr(v, "value", None)
            self.data_read += len(data) if isinstance(data, (bytes, bytearray, str)) else sum(len(x) for x in data if isinstance(x, (str, bytes))) if isinstance(data, list) else 0
            if self.data_read > 4 * self.hive_bytes:
                problems.append({"where": where, "what": "values",
                                 "error": "the values read in this walk hold more data than a %d-byte hive can: records that a value list names again and again; "
                                          "the values past that are not read" % self.hive_bytes})
                break
            raw.append(v)
        return raw
# END SHARED HIVE BOUNDS


try:
    from regipy.registry import RegistryHive
except ImportError:
    print(json.dumps({
        "error": "regipy is not installed",
        "hint": "python3 -m pip install --user regipy; scripts/toolbox.sh reports it as regipy-dump",
    }))
    raise SystemExit(1)

PARSER = "amcache_apps/3"
DEADLINE_SECONDS = 85             # the manifest allows 90
FILETIME_EPOCH = datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc)
UNIX_EPOCH = datetime.datetime(1970, 1, 1, tzinfo=datetime.timezone.utc)

# The numbered values of Root\File, by the published research regipy's Amcache plugin follows.
LEGACY_VALUES = {
    "0": "product_name",
    "1": "company_name",
    "2": "file_version_number",
    "3": "language_code",
    "4": "switchback_context",
    "5": "file_version",
    "6": "file_size",
    "7": "pe_header_hash",
    "9": "pe_header_checksum",
    "c": "file_description",
    "f": "linker_compile_time",
    "11": "last_modified_timestamp",
    "12": "created_timestamp",
    "15": "full_path",
    "17": "last_modified_timestamp_2",
    "100": "program_id",
    "101": "sha1",
}
LEGACY_FILETIMES = ("last_modified_timestamp", "created_timestamp", "last_modified_timestamp_2")
HASH_SHAPE = re.compile(r"^0000([0-9a-fA-F]{40})$")


def fail(message, **extra):
    print(json.dumps({"error": message, "status": "failed", "status_basis": "the tool stopped with an error (see error); no inventory key was read", **extra}))
    raise SystemExit(1)


def filetime(value):
    """ISO 8601 UTC with seven fractional digits, by integer arithmetic; None for 0 or a date past 9999."""
    try:
        value = int(value)
    except (TypeError, ValueError):
        return None
    if value <= 0:
        return None
    try:
        whole, ticks = divmod(value, 10_000_000)
        return (FILETIME_EPOCH + datetime.timedelta(seconds=whole)).strftime("%Y-%m-%dT%H:%M:%S") + ".%07dZ" % ticks
    except (OverflowError, ValueError):
        return None


def unix_seconds(value):
    """ISO 8601 UTC for a 32-bit Unix-epoch value (the PE linker timestamp); None for 0 or an unreadable one."""
    try:
        value = int(value)
    except (TypeError, ValueError):
        return None
    if value <= 0:
        return None
    try:
        return (UNIX_EPOCH + datetime.timedelta(seconds=value)).strftime("%Y-%m-%dT%H:%M:%SZ")
    except (OverflowError, ValueError):
        return None


def render(value):
    if isinstance(value, (bytes, bytearray)):
        return bytes(value).hex()
    return value


def stripped_hash(raw):
    """The 40 hex digits behind the four leading zeros an inventory hash is stored with; None for any other shape."""
    if isinstance(raw, str):
        m = HASH_SHAPE.match(raw)
        if m:
            return m.group(1).lower()
    return None


# The fields the tool puts in a row itself. A value whose NAME is one of these (a hive can hold a value called `layout`) would replace
# the tool's field and spoof the row's layout, volume, hash or times: it is kept under `value:<name>` instead.
OWN_FIELDS = {"layout", "volume", "key", "key_last_modified", "key_last_modified_filetime", "sha1_raw", "file_id_sha1",
              "linker_compile_time_utc"} | {n + suffix for n in LEGACY_FILETIMES for suffix in ("_utc", "_filetime")}


def set_value(row, name, value):
    row["value:" + name if name in OWN_FIELDS else name] = value


def legacy_row(volume_name, sub, bounds, where, problems):
    row = {"layout": "File", "volume": volume_name}
    # trim_values=False: regipy's default cuts a string to 256 characters and a binary value to 128 bytes.
    for v in bounds.values(sub, where, problems, trim_values=False):
        name = LEGACY_VALUES.get(str(v.name).lower(), str(v.name))
        set_value(row, name, render(v.value))
    if "linker_compile_time" in row:
        # A Unix-epoch 32-bit value from the PE header; not a FILETIME. The raw value stays in the row.
        row["linker_compile_time_utc"] = unix_seconds(row["linker_compile_time"])
    for name in LEGACY_FILETIMES:
        if name in row:
            row[name + "_utc"] = filetime(row[name])
            row[name + "_filetime"] = str(row[name])
    if "sha1" in row:
        row["sha1_raw"] = row["sha1"]
        row["sha1"] = stripped_hash(row["sha1_raw"])
    return row


def modern_row(sub, bounds, where, problems):
    row = {"layout": "InventoryApplicationFile"}
    for v in bounds.values(sub, where, problems, trim_values=False):
        set_value(row, str(v.name), render(v.value))
    if "FileId" in row:
        row["file_id_sha1"] = stripped_hash(row["FileId"])
    return row


def main():
    withhold_library_output()
    set_deadline(DEADLINE_SECONDS)
    install_signal_handlers(lambda signum: interrupted_answer(signum))
    try:
        args = json.load(sys.stdin)
    except ValueError as exc:
        fail("arguments are not valid JSON", reason=str(exc))
    if not isinstance(args, dict):
        fail("the arguments are one JSON object")

    hive = args.get("hive")
    if not isinstance(hive, str) or not hive:
        fail("hive is required: the path to Amcache.hve")
    limit = args.get("limit", 500)
    if not isinstance(limit, int) or isinstance(limit, bool) or limit < 1:
        fail("limit must be a positive integer", limit=args.get("limit"))

    try:
        hive_mode = os.stat(hive).st_mode
    except OSError:
        fail("no such hive", hive=hive)
    if not stat.S_ISREG(hive_mode):
        # A named pipe or a device would be opened and waited on: it is not read.
        fail("the hive is not a regular file, so it was not opened", hive=hive, not_attempted=1)
    try:
        h = RegistryHive(hive)
    except Exception as exc:
        fail("could not open the hive", hive=hive, reason=str(exc))
    bounds = HiveBounds(hive)

    entries = NoReplacePage("amcache_apps", [hive], limit)
    problem_page = NoReplacePage("amcache_apps-problems", [hive], 40)
    counts = {}
    failed = [0]
    stopped = [None]                                    # why the walk ended before the end of the inventory, or None

    class Problems:
        """What HiveBounds says about a list it cut or de-duplicated: a line of the problem page."""

        def append(self, item):
            problem_page.add("%s: %s" % (item["where"], item["error"]))

    bound_problems = Problems()

    def add(row, sub):
        last = getattr(getattr(sub, "header", None), "last_modified", 0)
        row["key"] = sub.name
        row["key_last_modified"] = filetime(last)
        row["key_last_modified_filetime"] = str(last)
        counts[row["layout"]] = counts.get(row["layout"], 0) + 1
        entries.add(row)

    def note(label, exc):
        failed[0] += 1
        problem_page.add("%s: %s: %s" % (label, type(exc).__name__, exc))

    def guarded(label, fn):
        try:
            fn()
        except Exception as exc:
            note(label, exc)

    def children(label, node):
        """The subkeys of `node`, at most the keys the hive can hold: a list that cannot be read is said (it is a row lost), never a traceback."""
        try:
            return bounds.subkeys(node, label, bound_problems)
        except Exception as exc:
            note(label, exc)
            return []

    def time_is_up(label):
        if stopped[0] is None and out_of_time():
            stopped[0] = "the tool's own time limit (%d seconds) was reached at %s; the inventory after it was not read" % (DEADLINE_SECONDS, label)
            problem_page.add(stopped[0])
        return stopped[0] is not None

    def key_at(path):
        """The key at `path`, or None when the hive has no such key; any other failure is a problem of the run."""
        try:
            return h.get_key(path)
        except Exception as exc:
            if type(exc).__name__ not in ("RegistryKeyNotFoundException", "NoRegistrySubkeysException"):
                note("looking for %s" % path, exc)
            return None

    layouts = []

    # The newer layout.
    inventory = key_at("\\Root\\InventoryApplicationFile")
    if inventory is not None:
        layouts.append("InventoryApplicationFile")
        for sub in children("InventoryApplicationFile", inventory):
            if time_is_up("InventoryApplicationFile"):
                break
            where = "InventoryApplicationFile\\%s" % getattr(sub, "name", "?")
            guarded(where, lambda sub=sub, where=where: add(modern_row(sub, bounds, where, bound_problems), sub))

    # The older layout: read as well when it is there, never instead.
    files = key_at("\\Root\\File")
    if files is not None:
        layouts.append("File")
        for volume in children("File", files):
            if time_is_up("File"):
                break
            for sub in children("File\\%s" % getattr(volume, "name", "?"), volume):
                if time_is_up("File\\%s" % getattr(volume, "name", "?")):
                    break
                where = "File\\%s\\%s" % (getattr(volume, "name", "?"), getattr(sub, "name", "?"))
                guarded(where, lambda volume=volume, sub=sub, where=where: add(legacy_row(volume.name, sub, bounds, where, bound_problems), sub))

    if not layouts:
        fail(
            "neither Amcache layout is present in this hive",
            hive=hive,
            looked_for=["\\Root\\InventoryApplicationFile", "\\Root\\File"],
            problems=problem_page.page,
        )

    if LibraryLog.messages:
        problem_page.add("regipy logged %d message(s) (%d of them errors) while reading; its text can hold bytes of a value or a name and is not shown" % (LibraryLog.messages, LibraryLog.errors))
    header = h.header
    dirty = header.primary_sequence_num != header.secondary_sequence_num
    logs = [hive + suffix for suffix in (".LOG1", ".LOG2", ".LOG") if os.path.isfile(hive + suffix)]
    page = entries.finish()
    problem_result = problem_page.finish()
    out = {
        "parser": PARSER,
        "status": "partial" if problem_result["matched"] or stopped[0] else "complete",
        "status_basis": ("%d problem(s) are named under problems" % problem_result["matched"] if problem_result["matched"] else "every row of both inventories was read")
                        + ("; " + stopped[0] if stopped[0] else ""),
        "hive": hive,
        "layouts_found": layouts,
        "rows_by_layout": counts,
        "entries": entries.page,
        "entry_count": page["matched"],
        "rows_failed": failed[0],
        "problems": problem_page.page,
        "problem_count": problem_result["matched"],
        "problems_not_listed": problem_result["matched"] - len(problem_page.page),
        "walk_stopped_by_time_limit": stopped[0] is not None,
        "library_messages_withheld": LibraryLog.messages,
        "hive_dirty": dirty,
        "hive_sequence_numbers": [header.primary_sequence_num, header.secondary_sequence_num],
        "transaction_logs_beside_hive": logs,
        "transaction_logs_replayed": False,
        "note": "An inventory of recorded binaries, not proof that any of them ran. Transaction logs are not replayed: "
                + ("this hive is dirty, so its newest state may be in the logs." if dirty else "the hive's sequence numbers agree."),
        **page,
    }
    if problem_result.get("all_results"):
        out["all_problems"] = problem_result["all_results"]
    print(json.dumps(out, indent=2))


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except Exception as exc:                                  # whatever hostile input does, the answer is JSON
        print(json.dumps({"error": "the read failed", "reason": "%s: %s" % (type(exc).__name__, exc)}))
        raise SystemExit(1)
