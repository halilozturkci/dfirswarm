#!/usr/bin/env python3
"""Walk BagMRU and say which folders a user opened in Explorer.

Shell bags record that a shell component opened a folder on an account, including
folders that no longer exist (a volume that was taken away, a share that has been
decommissioned). They do not say who opened it, that a file in it was opened, or
when it was first or last viewed.

Two roots, depending on the Windows version and the hive:

    UsrClass.dat  Local Settings\\Software\\Microsoft\\Windows\\Shell\\BagMRU
    NTUSER.DAT    Software\\Microsoft\\Windows\\Shell\\BagMRU
                  Software\\Microsoft\\Windows\\ShellNoRoam\\BagMRU   (older)

Each key holds one numbered value per child, and that value is a shell item.
Shell items are a family of formats, so this decodes the ones that carry a name
and, for anything else, falls back to pulling the readable strings out of the
item and says it did. A name recovered by fallback is a candidate, found by
search, and is labelled as one (`decoded: strings`, `long_name_from: strings`); a
name read from a layout is labelled `layout`, and only where the layout is one this
reader applies (a shell item extension block of version 3, 7, 8 or 9, read at the offset the
libfwsi notes give for its version and only when the block's own name offset, the 2-byte field
at 0x10, agrees). Every BagMRU root the
hive has is walked and named (a hive can hold the Shell and the ShellNoRoam trees at
once), each entry says which, and a numbered value with no key under it is listed, not
dropped. A folder in a bag is a folder some shell opened on this account; the artefact
does not say by whom, and its times are two clocks (see the note in the answer).

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
import stat
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

FILETIME_EPOCH = datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc)
BEEF0004 = 0xBEEF0004
PARSER = "shellbags/3"
MAX_DEPTH = 128
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
    """ISO 8601 UTC with seven fractional digits, by integer arithmetic; None for 0 or an unreadable value."""
    try:
        value = int(value)
        if value <= 0:
            return None
        whole, ticks = divmod(value, 10_000_000)
        return (FILETIME_EPOCH + datetime.timedelta(seconds=whole)).strftime("%Y-%m-%dT%H:%M:%S") + ".%07dZ" % ticks
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


# Where the long name begins in a 0xBEEF0004 (file entry) extension block, by its version, as the libfwsi notes
# lay the block out: size (2), version (2), the signature (4), the FAT creation and access times (4 each), then
# the 2-byte field at 0x10 (the offset of the long name, which is how a block says where its name is), and the
# fields that differ by version before the NUL-terminated UTF-16LE long name: version 3 has a 2-byte long-string
# size and the name at 0x14, version 7 a file reference and the name at 0x26, version 8 four more bytes and the
# name at 0x2A, version 9 four more again and the name at 0x2E. The name is followed, from version 7 on, by the
# localised name when the item has one (`@shell32.dll,-21813`), and the block ends with the 2-byte offset of its
# own start in the item. Windows 10 writes version 9: every block of one real Windows 10 UsrClass.dat read here
# had 0x2E in the 0x10 field and its name there.
LONG_NAME_AT = {3: 0x14, 7: 0x26, 8: 0x2A, 9: 0x2E}
LOCALISED_FROM = 7


def utf16_string(block, at):
    """The NUL-terminated UTF-16LE string at `at` in `block`, with the offset after its terminator; None when it
    is not terminated inside the block."""
    end = at
    while end + 1 < len(block) and (block[end] or block[end + 1]):
        end += 2
    if end + 1 >= len(block):
        return None
    return block[at:end].decode("utf-16-le", "replace"), end + 2


def extension_block(data):
    """The beef0004 block: two more DOS timestamps, and the long name.

    The timestamps sit at fixed offsets in every version. The block is bounded by the size it declares. The long
    name is read from its documented offset only for the versions in LONG_NAME_AT, only when the block's own name
    offset (the 2-byte field at 0x10) says the same offset, and only when what is there is a printable string that
    ends inside the block. For any other version, or when a check fails, the longest wide string in the block is
    offered instead and the output says it was found by search (`long_name_from: strings`): a candidate, not a
    decode, and `extension_layout` says why the layout was not applied. A name read from a layout guessed for a
    version this reader does not know would be worse than a candidate.
    """
    at = data.find(struct.pack("<I", BEEF0004))
    if at < 4:
        return {}
    start = at - 4
    if start + 0x12 > len(data):
        return {}
    size, version = struct.unpack_from("<HH", data, start)
    created, accessed = struct.unpack_from("<II", data, start + 8)
    fits = 0x12 <= size <= len(data) - start
    block = data[start:start + size] if fits else data[start:]
    out = {"created": dos_datetime(created), "accessed": dos_datetime(accessed),
           "extension_version": version, "extension_block_size": size}
    if not fits:
        out["extension_block_size_fits"] = False
    expected = LONG_NAME_AT.get(version)
    own = struct.unpack_from("<H", block, 0x10)[0] if len(block) >= 0x12 else None
    why = None
    if expected is None:
        why = "not decoded for this version"
    elif own != expected:
        why = "not decoded: the block's own name offset (0x10) is 0x%x and this reader expects 0x%x for version %d" % (own or 0, expected, version)
    else:
        got = utf16_string(block, expected)
        if got is None or not got[0] or not got[0].isprintable():
            why = "not decoded: what sits at 0x%x is not a printable string that ends inside the block" % expected
        else:
            out["long_name"], out["long_name_from"], out["extension_layout"] = got[0], "layout", "decoded"
            if version >= LOCALISED_FROM:
                # The localised name, when the item has one, follows the long name and ends before the block's last two bytes.
                more = utf16_string(block, got[1]) if got[1] + 2 <= len(block) - 2 else None
                if more is not None and more[0] and more[0].isprintable() and more[1] <= len(block) - 2:
                    out["localized_name"] = more[0]
                    out["localized_name_from"] = "the string after the long name"
    if why is not None:
        out["extension_layout"] = why
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


def values_of(key):
    """The values of a key whole: regipy's iter_values cuts a binary value to 128 bytes unless told not to, and a
    shell item is often longer. (A reader stub that does not take the argument is called without it.)"""
    try:
        return key.iter_values(trim_values=False)
    except TypeError:
        return key.iter_values()


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


def safe_nearest_key(hive, path):
    """nearest_key, which walks a hive that may be the damaged one: a failure of its own is said, not raised."""
    try:
        return nearest_key(hive, path)
    except Exception as exc:
        return {"deepest_found": None, "missing": None, "subkeys_there": [], "nearest_key_failed": "%s: %s" % (type(exc).__name__, exc)}


def main():
    try:
        args = json.load(sys.stdin)
    except ValueError as exc:
        fail("arguments are not valid JSON", reason=str(exc))
    if not isinstance(args, dict):
        fail("the arguments are one JSON object")

    hive_path = args.get("hive")
    if not isinstance(hive_path, str) or not hive_path:
        fail("hive is required: an extracted UsrClass.dat or NTUSER.DAT")
    try:
        hive_mode = os.stat(hive_path).st_mode
    except OSError:
        fail("no such hive", hive=hive_path)
    if not stat.S_ISREG(hive_mode):
        # A named pipe or a device would be opened and waited on: it is not read.
        fail("the hive is not a regular file, so it was not opened", hive=hive_path, not_attempted=1)

    limit = args.get("limit", 500)
    if not isinstance(limit, int) or isinstance(limit, bool) or limit < 1:
        fail("limit must be a positive integer", limit=args.get("limit"))
    max_depth = args.get("max_depth", 24)
    if not isinstance(max_depth, int) or isinstance(max_depth, bool) or not 1 <= max_depth <= MAX_DEPTH:
        fail("max_depth must be a whole number from 1 to %d" % MAX_DEPTH, max_depth=args.get("max_depth"))
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
    found_roots = []
    tried = []
    for candidate in roots:
        try:
            found_roots.append((rooted_key(hive, candidate), candidate))
        except Exception as exc:
            tried.append({"key": candidate, "why": str(exc), **safe_nearest_key(hive, candidate)})
    if not found_roots:
        fail("no BagMRU root in this hive", hive=hive_path, tried=tried)

    key = [hive_path, [r[1] for r in found_roots], contains, max_depth]
    entries = LosslessPage("shellbags", key, limit)
    problems = LosslessPage("shellbags-problems", key, 40)
    stopped = LosslessPage("shellbags-not-walked", key, 40)
    orphans = LosslessPage("shellbags-orphan-values", key, 40)
    counts = {"strings": 0, "orphans": 0, "other_values": 0, "walked": 0}

    def item_entry(raw, slot_name, key_path, parent_path, depth, order, root_path, header=None, orphan=False):
        try:
            item = decode_item(bytes(raw)) if isinstance(raw, (bytes, bytearray)) else \
                {"type": "no shell item on the parent", "name": slot_name, "decoded": "none"}
        except Exception as exc:                              # a shell item that defeats the reader is listed as such
            item = {"type": "undecodable", "name": "", "decoded": "none", "error": "%s: %s" % (type(exc).__name__, exc)}
            problems.add({"key": key_path + "\\" + slot_name, "why": "the shell item could not be decoded: %s: %s" % (type(exc).__name__, exc)})
        name = item.get("name") or ""
        path = (parent_path + "\\" + name).strip("\\") if name else parent_path
        entry = {
            "root": root_path,
            "path": path,
            "name": name,
            "registry_key": key_path + "\\" + slot_name,
            "slot": slot_name,
            "depth": depth,
            "mru_position": order.index(int(slot_name)) if slot_name.isdigit() and int(slot_name) in order else None,
            "item": item,
        }
        if isinstance(raw, (bytes, bytearray)):
            entry["item_bytes"] = len(raw)
        if orphan:
            entry["no_subkey"] = True
        if header is not None:
            entry["key_last_written"] = filetime(header.last_modified)
            entry["key_last_written_filetime"] = str(header.last_modified)
        return entry, path

    visited = set()

    def walk(key, key_path, parent_path, depth, root_path):
        counts["walked"] += 1
        # A key whose subkey list was already reached is a cycle (or a list two keys share): it is said, not walked again.
        lid = getattr(getattr(key, "header", None), "subkeys_list_offset", None)
        if lid is not None and getattr(key, "subkey_count", 0):
            if lid in visited:
                problems.add({"key": key_path, "why": "its subkey list (offset %s) was already walked: a cycle, or a list two keys share; not walked again" % lid})
                return
            visited.add(lid)
        if depth > max_depth:
            # Name the key where the walk stopped, and how much lies under it.
            try:
                below = sum(1 for _ in key.iter_subkeys())
            except Exception as exc:
                problems.add({"key": key_path, "why": "subkeys unreadable: %s" % exc})
                return
            if below:
                stopped.add({"key": key_path, "depth": depth, "subkeys": below})
            return
        values = {}
        try:
            for value in values_of(key):
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
        names = {s.name for s in subkeys}
        for sub in subkeys:
            entry, path = item_entry(values.get(sub.name), sub.name, key_path, parent_path, depth, order, root_path, getattr(sub, "header", None))
            if not contains or contains in path.lower():
                entries.add(entry)
                if entry["item"].get("decoded") == "strings":
                    counts["strings"] += 1
            walk(sub, key_path + "\\" + sub.name, path, depth + 1, root_path)
        # A numbered value with no key under it is a shell item with no bag of its own: decoded and listed, not dropped.
        for vname, raw in values.items():
            if vname in names:
                continue
            if vname.isdigit():
                entry, path = item_entry(raw, vname, key_path, parent_path, depth, order, root_path, orphan=True)
                counts["orphans"] += 1
                orphans.add(entry)
                if not contains or contains in path.lower():
                    entries.add(entry)
                    if entry["item"].get("decoded") == "strings":
                        counts["strings"] += 1
            else:
                counts["other_values"] += 1

    for root_key, root_path in found_roots:
        walk(root_key, root_path, "", 1, root_path)

    page = entries.finish()
    problem_page = problems.finish()
    stopped_page = stopped.finish()
    orphan_page = orphans.finish()
    out = {
        "parser": PARSER,
        "status": "partial" if problem_page["matched"] or stopped_page["matched"] else "complete",
        "hive": hive_path,
        "root": found_roots[0][1],
        "roots_walked": [r[1] for r in found_roots],
        "roots_not_found": [t["key"] for t in tried],
        "keys_walked": counts["walked"],
        "entries": entries.page,
        "entry_count": page["matched"],
        "recovered_by_strings": counts["strings"],
        **page,
        "not_walked_below_max_depth": stopped.page,
        "not_walked_count": stopped_page["matched"],
        "values_without_subkey": orphans.page,
        "values_without_subkey_count": orphan_page["matched"],
        "other_values_ignored": counts["other_values"],
        "problems": problems.page,
        "problem_count": problem_page["matched"],
        "note": "key_last_written is a kernel FILETIME in UTC. The item's own created, "
                "modified and accessed values are DOS timestamps in the machine's local "
                "time, to two seconds; convert them with the timezone from "
                "SYSTEM\\ControlSet00n\\Control\\TimeZoneInformation and say so. A name from "
                "`decoded: strings` or `long_name_from: strings` is a candidate found by search, not a decode.",
    }
    if problem_page.get("all_results"):
        out["all_problems"] = problem_page["all_results"]
    if stopped_page.get("all_results"):
        out["all_not_walked"] = stopped_page["all_results"]
    if orphan_page.get("all_results"):
        out["all_values_without_subkey"] = orphan_page["all_results"]
    print(json.dumps(out, indent=2, default=str))


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except Exception as exc:                                  # whatever hostile input does, the answer is JSON
        print(json.dumps({"error": "the read failed", "reason": "%s: %s" % (type(exc).__name__, exc)}))
        sys.exit(1)
