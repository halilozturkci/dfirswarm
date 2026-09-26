#!/usr/bin/env python3
"""Walk BagMRU and say which folders a user opened in Explorer.

Shell bags are the artefact that proves someone navigated to a directory that
no longer exists: a folder on a stick that was taken away, a share that has been
decommissioned, a directory that was deleted after it was emptied. Nothing else
in Windows keeps that.

Two roots, depending on the Windows version and the hive:

    UsrClass.dat  Local Settings\\Software\\Microsoft\\Windows\\Shell\\BagMRU
    NTUSER.DAT    Software\\Microsoft\\Windows\\Shell\\BagMRU
                  Software\\Microsoft\\Windows\\ShellNoRoam\\BagMRU   (older)

Each key holds one numbered value per child, and that value is a shell item.
Shell items are a family of formats, so this decodes the ones that carry a name
and, for anything else, falls back to pulling the readable strings out of the
item and says it did. A name recovered by fallback is still evidence; a name
invented by a parser that guessed at the layout is not, which is why the two are
labelled differently in the output.

Two traps the output is shaped around:

- The key's last-write time is a real FILETIME set by the kernel. The shell
  item's own timestamps are **DOS date and time, in the machine's local time**,
  with two-second resolution. Do not put them in a UTC timeline without saying
  what you converted from.
- A path here means the folder was browsed, not that the folder still exists and
  not that a file in it was opened.

The whole tree is walked. The page returned inline is `limit` long, and when
more entries match the whole list is written to a file the output names. A key
below max_depth whose subkeys were not walked is named in the output, never
passed over in silence.
"""
import datetime
import json
import os
import re
import struct
import sys

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

FILETIME_EPOCH = datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc)
BEEF0004 = 0xBEEF0004
DEFAULT_ROOTS = [
    r"Local Settings\Software\Microsoft\Windows\Shell\BagMRU",
    r"Software\Microsoft\Windows\Shell\BagMRU",
    r"Software\Microsoft\Windows\ShellNoRoam\BagMRU",
    r"Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\BagMRU",
]


def fail(message, **extra):
    print(json.dumps({"error": message, **extra}))
    raise SystemExit(1)


def filetime(value):
    try:
        return (FILETIME_EPOCH + datetime.timedelta(microseconds=int(value) // 10)).isoformat().replace("+00:00", "Z")
    except (OverflowError, OSError, TypeError, ValueError):
        return None


def dos_datetime(value):
    """FAT date and time, in the machine's own local time. Never call it UTC."""
    if not value:
        return None
    date, time = value & 0xFFFF, (value >> 16) & 0xFFFF
    year = ((date >> 9) & 0x7F) + 1980
    month, day = (date >> 5) & 0x0F, date & 0x1F
    hour, minute, second = (time >> 11) & 0x1F, (time >> 5) & 0x3F, (time & 0x1F) * 2
    if not (1 <= month <= 12 and 1 <= day <= 31 and hour < 24 and minute < 60 and second < 60):
        return None
    return "%04d-%02d-%02dT%02d:%02d:%02d (local)" % (year, month, day, hour, minute, second)


def readable(data):
    """Whatever a human would recognise in the item, when the layout is unknown."""
    wide = re.findall(rb"(?:[\x20-\x7e]\x00){3,}", data)
    if wide:
        return max((w.decode("utf-16-le", "replace") for w in wide), key=len)
    narrow = re.findall(rb"[\x20-\x7e]{4,}", data)
    return max((n.decode("ascii", "replace") for n in narrow), key=len) if narrow else ""


def wide_strings(data):
    return [w.decode("utf-16-le", "replace") for w in re.findall(rb"(?:[^\x00][\x00]){2,}", data)]


def extension_block(data):
    """The beef0004 block: two more DOS timestamps, and the long name.

    The timestamps sit at fixed offsets in every version. The long name does not:
    it begins at 0x12 up to version 6 and after a file reference from version 7,
    and later versions have added fields between. So the offset is tried first
    and the answer is checked; when it does not hold, the longest wide string in
    the block is used instead and the output says which of the two it was. A name
    found by search is still evidence. A name produced by a parser guessing at a
    layout it does not know is not.
    """
    at = data.find(struct.pack("<I", BEEF0004))
    if at < 4:
        return {}
    start = at - 4
    if start + 0x12 > len(data):
        return {}
    version = struct.unpack_from("<H", data, start + 2)[0]
    created, accessed = struct.unpack_from("<II", data, start + 8)
    out = {"created": dos_datetime(created), "accessed": dos_datetime(accessed),
           "extension_version": version}
    block = data[start:]
    cursor = 0x12
    if version >= 7:
        cursor = 0x26                      # unknown, file reference, unknown, string size
    candidate = ""
    if cursor + 2 <= len(block):
        end = block.find(b"\x00\x00", cursor)
        if end > cursor:
            if (end - cursor) % 2:
                end += 1
            candidate = block[cursor:end].decode("utf-16-le", "replace").strip("\x00")
    if candidate and candidate.isprintable():
        out["long_name"] = candidate
        out["long_name_from"] = "layout"
    else:
        found = [w for w in wide_strings(block) if w.isprintable()]
        if found:
            out["long_name"] = max(found, key=len)
            out["long_name_from"] = "strings"
    return out


def decode_item(data):
    """Name what the shell item is, and say how the name was recovered."""
    if len(data) < 3:
        return {"type": "empty", "decoded": "none"}
    klass = data[2]
    item = {"class": "0x%02x" % klass}
    if klass == 0x1F:
        item["type"] = "root folder"
        if len(data) >= 20:
            # Data1-3 little-endian at 4, Data4 as stored at 12 (it was read
            # at 10, two bytes early: My Computer came out -6910-A2D808002B30).
            guid = struct.unpack_from("<IHH", data, 4) + (data[12:14].hex().upper(), data[14:20].hex().upper())
            item["guid"] = "{%08X-%04X-%04X-%s-%s}" % guid
        item["decoded"] = "layout"
        item["name"] = item.get("guid", "")
        return item
    if klass == 0x2F:
        item["type"] = "volume"
        item["name"] = data[3:data.find(b"\x00", 3) if data.find(b"\x00", 3) > 0 else len(data)].decode("ascii", "replace")
        item["decoded"] = "layout"
        return item
    if klass & 0x70 == 0x30:
        item["type"] = "directory" if klass & 0x01 else "file"
        if len(data) >= 14:
            size, modified = struct.unpack_from("<II", data, 4)
            item["file_size"] = size
            item["modified"] = dos_datetime(modified)
        end = data.find(b"\x00", 14)
        primary = data[14:end if end > 14 else len(data)].decode("latin-1", "replace")
        item.update(extension_block(data))
        item["name"] = item.get("long_name") or primary
        item["short_name"] = primary
        item["decoded"] = "layout"
        return item
    item["type"] = "unrecognised"
    item["name"] = readable(data)
    item["decoded"] = "strings"
    return item


def binary(value):
    """A REG_BINARY value as bytes. regipy hands one over as a hex string (5.x
    and 6.x alike), and this tool took only bytes: in the third CTF round no
    shell item was ever decoded, every entry said "no shell item on the
    parent" and MRUListEx gave no order."""
    if isinstance(value, (bytes, bytearray)):
        return bytes(value)
    if isinstance(value, str) and len(value) % 2 == 0 and re.fullmatch(r"[0-9A-Fa-f]*", value):
        return bytes.fromhex(value)
    return None


def mru_order(values):
    raw = values.get("MRUListEx")
    if not isinstance(raw, (bytes, bytearray)):
        return []
    order = []
    for i in range(0, len(raw) - 3, 4):
        index = struct.unpack_from("<i", raw, i)[0]
        if index < 0:
            break
        order.append(index)
    return order


def rooted_key(hive, path):
    """The key at `path`, from the hive's root. regipy's get_key takes the
    first part of a path that does not start with a backslash for the root's
    own name and drops it: "Local Settings\\...\\BagMRU" in a UsrClass.dat was
    not found, and in an NTUSER.DAT it answered Software\\...\\BagMRU under
    the name asked for. The path is rooted here, the root's name dropped when
    the caller gave it, and / taken for \\."""
    parts = [p for p in str(path).replace("/", "\\").split("\\") if p]
    if parts and parts[0].lower() == (hive.root.name or "").lower():
        parts = parts[1:]
    return hive.get_key("\\" + "\\".join(parts)) if parts else hive.root


def nearest_key(hive, path):
    """Where `path` stops existing: the deepest key of it the hive has, the
    part that is not there, and the names that are. A caller who guessed a
    key (a printer key one Windows version keeps and another does not, a
    control set an offline SYSTEM hive numbers) picks from these instead of
    guessing again."""
    parts = [p for p in str(path).replace("/", "\\").split("\\") if p]
    if parts and parts[0].lower() == (hive.root.name or "").lower():
        parts = parts[1:]
    node, found = hive.root, []
    for part in parts:
        kids = list(node.iter_subkeys())
        match = next((k for k in kids if k.name.lower() == part.lower()), None)
        if match is None:
            return {"deepest_found": "\\" + "\\".join(found), "missing": part,
                    "subkeys_there": sorted(k.name for k in kids)}
        node, found = match, found + [match.name]
    return {"deepest_found": "\\" + "\\".join(found), "missing": None, "subkeys_there": []}


def main():
    try:
        args = json.load(sys.stdin)
    except ValueError as exc:
        fail("arguments are not valid JSON", reason=str(exc))

    hive_path = args.get("hive")
    if not isinstance(hive_path, str) or not hive_path:
        fail("hive is required: an extracted UsrClass.dat or NTUSER.DAT")
    if not os.path.isfile(hive_path):
        fail("no such hive", hive=hive_path)

    limit = args.get("limit", 500)
    if not isinstance(limit, int) or isinstance(limit, bool) or limit < 1:
        fail("limit must be a positive integer", limit=args.get("limit"))
    max_depth = args.get("max_depth", 24)
    if not isinstance(max_depth, int) or isinstance(max_depth, bool) or max_depth < 1:
        fail("max_depth must be a positive integer", max_depth=args.get("max_depth"))
    contains = (args.get("contains") or "").lower()

    try:
        from regipy.registry import RegistryHive
    except ImportError as exc:
        fail("regipy is not installed: python3 -m pip install regipy", reason=str(exc))

    try:
        hive = RegistryHive(hive_path)
    except Exception as exc:
        fail("regipy cannot open this hive", hive=hive_path, reason="%s: %s" % (type(exc).__name__, exc))

    roots = [args["key"]] if args.get("key") else DEFAULT_ROOTS
    root_key, root_path = None, None
    tried = []
    for candidate in roots:
        try:
            root_key = rooted_key(hive, candidate)
            root_path = candidate
            break
        except Exception as exc:
            tried.append({"key": candidate, "why": str(exc), **nearest_key(hive, candidate)})
    if root_key is None:
        fail("no BagMRU root in this hive", hive=hive_path, tried=tried)

    key = [hive_path, root_path, contains, max_depth]
    entries = LosslessPage("shellbags", key, limit)
    problems = LosslessPage("shellbags-problems", key, 40)
    not_walked = []
    counts = {"strings": 0}

    def walk(key, key_path, parent_path, depth):
        if depth > max_depth:
            # Name the key where the walk stopped, and how much lies under it.
            try:
                below = sum(1 for _ in key.iter_subkeys())
            except Exception as exc:
                problems.add({"key": key_path, "why": "subkeys unreadable: %s" % exc})
                return
            if below:
                not_walked.append({"key": key_path, "depth": depth, "subkeys": below})
            return
        values = {}
        try:
            for value in key.iter_values():
                raw = binary(value.value)
                values[value.name] = raw if raw is not None else value.value
        except Exception as exc:
            problems.add({"key": key_path, "why": "values unreadable: %s" % exc})
        order = mru_order(values)
        try:
            subkeys = list(key.iter_subkeys())
        except Exception as exc:
            problems.add({"key": key_path, "why": "subkeys unreadable: %s" % exc})
            return
        for sub in subkeys:
            raw = values.get(sub.name)
            item = decode_item(bytes(raw)) if isinstance(raw, (bytes, bytearray)) else \
                {"type": "no shell item on the parent", "name": sub.name, "decoded": "none"}
            name = item.get("name") or ""
            path = (parent_path + "\\" + name).strip("\\") if name else parent_path
            header = getattr(sub, "header", None)
            entry = {
                "path": path,
                "name": name,
                "registry_key": key_path + "\\" + sub.name,
                "slot": sub.name,
                "depth": depth,
                "mru_position": order.index(int(sub.name)) if sub.name.isdigit() and int(sub.name) in order else None,
                "item": item,
            }
            if header is not None:
                entry["key_last_written"] = filetime(header.last_modified)
            if not contains or contains in path.lower():
                entries.add(entry)
                if item.get("decoded") == "strings":
                    counts["strings"] += 1
            walk(sub, key_path + "\\" + sub.name, path, depth + 1)

    walk(root_key, root_path, "", 1)

    page = entries.finish()
    problem_page = problems.finish()
    out = {
        "hive": hive_path,
        "root": root_path,
        "entries": entries.page,
        "entry_count": page["matched"],
        "recovered_by_strings": counts["strings"],
        **page,
        "not_walked_below_max_depth": not_walked,
        "problems": problems.page,
        "problem_count": problem_page["matched"],
        "note": "key_last_written is a kernel FILETIME in UTC. The item's own created, "
                "modified and accessed values are DOS timestamps in the machine's local "
                "time, to two seconds; convert them with the timezone from "
                "SYSTEM\\\\ControlSet00n\\\\Control\\\\TimeZoneInformation and say so.",
    }
    if problem_page.get("all_results"):
        out["all_problems"] = problem_page["all_results"]
    print(json.dumps(out, indent=2, default=str))


if __name__ == "__main__":
    main()
