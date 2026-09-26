#!/usr/bin/env python3
"""Program execution from an Amcache.hve registry hive.

Amcache answers "what ran on this box, and what was its SHA-1" better than
anything else on a Windows image, and every measured case that wanted it did
it by hand through a generic registry dumper. The key layout differs between
Windows versions, so this reads whichever of the two is present and says
which one it found rather than silently returning nothing.

  Root\\File\\<volume>\\<id>                  Windows 7/8
  Root\\InventoryApplicationFile\\<id>        Windows 10 and later
"""
import datetime
import json
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

    def _write(self, row: object) -> None:
        assert self._out is not None
        self._out.write(json.dumps(row, ensure_ascii=False, default=str))
        self._out.write("\n")

    def add(self, row: object) -> None:
        self.total += 1
        if len(self.page) < self.limit:
            self.page.append(row)
            return
        if self._out is None:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            fd, name = tempfile.mkstemp(
                dir=self.path.parent, prefix=f".{self.path.name}-"
            )
            self._tmp = Path(name)
            self._out = os.fdopen(fd, "w", encoding="utf-8")
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
            self._out.flush()
            os.fsync(self._out.fileno())
            self._out.close()
            assert self._tmp is not None
            os.replace(self._tmp, self.path)
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

FILETIME_EPOCH = datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc)

# The numbered values of Root\File on Windows 7/8. Named ones are used as-is.
WIN7_VALUES = {
    "0": "product_name",
    "1": "company_name",
    "6": "file_size",
    "c": "file_version",
    "f": "link_date",
    "15": "full_path",
    "100": "program_id",
    "101": "sha1",
}

WIN10_KEEP = (
    "Name", "LowerCaseLongPath", "Size", "ProductName", "Publisher",
    "Version", "BinFileVersion", "FileId", "LinkDate", "ProgramId",
)


def fail(message, **extra):
    print(json.dumps({"error": message, **extra}))
    raise SystemExit(1)


def filetime(value):
    try:
        value = int(value)
    except (TypeError, ValueError):
        return None
    if value <= 0:
        return None
    try:
        return (FILETIME_EPOCH + datetime.timedelta(microseconds=value // 10)).isoformat().replace("+00:00", "Z")
    except OverflowError:
        return None


def render(value):
    if isinstance(value, (bytes, bytearray)):
        return bytes(value).hex()
    return value


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
        h = RegistryHive(hive)
    except Exception as exc:
        fail("could not open the hive", hive=hive, reason=str(exc))

    entries = LosslessPage("amcache_apps", [hive], limit)
    layout = None

    def add(values, key_name, last_modified):
        row = {"key": key_name, "key_last_modified": filetime(last_modified)}
        row.update(values)
        entries.add(row)

    # Windows 10 and later.
    try:
        inventory = h.get_key("\\Root\\InventoryApplicationFile")
    except Exception:
        inventory = None
    if inventory is not None:
        layout = "InventoryApplicationFile"
        for sub in inventory.iter_subkeys():
            values = {}
            for v in sub.iter_values():
                if v.name in WIN10_KEEP:
                    values[v.name] = render(v.value)
            add(values, sub.name, getattr(getattr(sub, "header", None), "last_modified", 0))

    # Windows 7 and 8.
    if layout is None:
        try:
            files = h.get_key("\\Root\\File")
        except Exception:
            files = None
        if files is not None:
            layout = "File"
            for volume in files.iter_subkeys():
                for sub in volume.iter_subkeys():
                    values = {"volume": volume.name}
                    for v in sub.iter_values():
                        name = WIN7_VALUES.get(str(v.name).lower(), str(v.name))
                        values[name] = render(v.value)
                    if "link_date" in values:
                        values["link_date_utc"] = filetime(values["link_date"])
                    add(values, sub.name, getattr(getattr(sub, "header", None), "last_modified", 0))

    if layout is None:
        fail(
            "neither Amcache layout is present in this hive",
            hive=hive,
            looked_for=["\\Root\\InventoryApplicationFile", "\\Root\\File"],
        )

    page = entries.finish()
    print(json.dumps({
        "hive": hive,
        "layout": layout,
        "entries": entries.page,
        "entry_count": page["matched"],
        **page,
    }, indent=2))


if __name__ == "__main__":
    main()
