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

try:
    from regipy.registry import RegistryHive
except ImportError:
    print(json.dumps({
        "error": "regipy is not installed",
        "hint": "python3 -m pip install --user regipy; scripts/toolbox.sh reports it as regipy-dump",
    }))
    raise SystemExit(1)

PARSER = "amcache_apps/2"
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
    print(json.dumps({"error": message, **extra}))
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


def legacy_row(volume_name, sub):
    row = {"layout": "File", "volume": volume_name}
    # trim_values=False: regipy's default cuts a string to 256 characters and a binary value to 128 bytes.
    for v in sub.iter_values(trim_values=False):
        name = LEGACY_VALUES.get(str(v.name).lower(), str(v.name))
        row[name] = render(v.value)
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


def modern_row(sub):
    row = {"layout": "InventoryApplicationFile"}
    for v in sub.iter_values(trim_values=False):
        row[str(v.name)] = render(v.value)
    if "FileId" in row:
        row["file_id_sha1"] = stripped_hash(row["FileId"])
    return row


def main():
    try:
        args = json.load(sys.stdin)
    except ValueError as exc:
        fail("arguments are not valid JSON", reason=str(exc))

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

    entries = LosslessPage("amcache_apps", [hive], limit)
    counts = {}
    problems = []
    failed = [0]
    unlisted = [0]

    def add(row, sub):
        last = getattr(getattr(sub, "header", None), "last_modified", 0)
        row["key"] = sub.name
        row["key_last_modified"] = filetime(last)
        row["key_last_modified_filetime"] = str(last)
        counts[row["layout"]] = counts.get(row["layout"], 0) + 1
        entries.add(row)

    def note(label, exc):
        failed[0] += 1
        if len(problems) < 20:
            problems.append("%s: %s: %s" % (label, type(exc).__name__, exc))
        else:
            unlisted[0] += 1

    def guarded(label, fn):
        try:
            fn()
        except Exception as exc:
            note(label, exc)

    def children(label, node):
        """The subkeys of `node`: a list that cannot be read is said (it is a row lost), never a traceback."""
        try:
            return list(node.iter_subkeys() or [])
        except Exception as exc:
            note(label, exc)
            return []

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
            guarded("InventoryApplicationFile\\%s" % getattr(sub, "name", "?"), lambda sub=sub: add(modern_row(sub), sub))

    # The older layout: read as well when it is there, never instead.
    files = key_at("\\Root\\File")
    if files is not None:
        layouts.append("File")
        for volume in children("File", files):
            for sub in children("File\\%s" % getattr(volume, "name", "?"), volume):
                guarded("File\\%s\\%s" % (getattr(volume, "name", "?"), getattr(sub, "name", "?")), lambda volume=volume, sub=sub: add(legacy_row(volume.name, sub), sub))

    if not layouts:
        fail(
            "neither Amcache layout is present in this hive",
            hive=hive,
            looked_for=["\\Root\\InventoryApplicationFile", "\\Root\\File"],
            problems=problems,
        )

    header = h.header
    dirty = header.primary_sequence_num != header.secondary_sequence_num
    logs = [hive + suffix for suffix in (".LOG1", ".LOG2", ".LOG") if os.path.isfile(hive + suffix)]
    page = entries.finish()
    out = {
        "parser": PARSER,
        "status": "partial" if failed[0] else "complete",
        "hive": hive,
        "layouts_found": layouts,
        "rows_by_layout": counts,
        "entries": entries.page,
        "entry_count": page["matched"],
        "rows_failed": failed[0],
        "problems": problems,
        "problems_not_listed": unlisted[0],
        "hive_dirty": dirty,
        "hive_sequence_numbers": [header.primary_sequence_num, header.secondary_sequence_num],
        "transaction_logs_beside_hive": logs,
        "transaction_logs_replayed": False,
        "note": "An inventory of recorded binaries, not proof that any of them ran. Transaction logs are not replayed: "
                + ("this hive is dirty, so its newest state may be in the logs." if dirty else "the hive's sequence numbers agree."),
        **page,
    }
    print(json.dumps(out, indent=2))


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except Exception as exc:                                  # whatever hostile input does, the answer is JSON
        print(json.dumps({"error": "the read failed", "reason": "%s: %s" % (type(exc).__name__, exc)}))
        raise SystemExit(1)
