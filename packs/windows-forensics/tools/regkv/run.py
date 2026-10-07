#!/usr/bin/env python3
"""Read a Windows registry hive with regipy: a key's values, its subkeys, and a bounded recursive listing.

What it is: a reader, not a decoder. A binary value comes back as hex and nothing more: UserAssist, ShimCache,
BAM, SAM and ShellBag values are not decoded here, and a typed reading of any of them needs a decoder that
knows its layout and its Windows version. Every value carries its registry type and length beside its
value, and nothing is cut (regipy's default trims a value to 256 characters; this reads them whole).

Completeness is said, not assumed. A key or value that cannot be read is named under `problems`, a key that
declares more values than were read is a problem too, a branch the walk did not enter (depth limit, node limit,
an error, or a subkey list that was already reached: a cycle) under `stopped_branches`, and the answer says
whether the hive is dirty (its two sequence numbers differ: its newest state may be in the .LOG files) and which
transaction logs sit beside it. The logs are NOT replayed here. The inline listing holds the first 2000 keys;
every key listed is also in the file `all_subkeys` names when there are more, and the answer is then `partial`.
depth is 0 to 128, because the nested listing is a JSON document and a deeper one cannot be written.

SENSITIVE OUTPUT. A value whose name says password, secret, token or credential, the values of the LSA secrets
and cached-logon keys of a SECURITY hive, and the V value of each SAM user (which holds password verifiers) are
registry material that can be a secret. Their text and bytes are never in the answer: the value is replaced by
a marker that holds its length, and `sensitive_values_withheld` lists key, name, type and length. No flag brings
one back; this tool produces no secret and has no capability to recover one.

The key path is read from the hive's root, a leading backslash or not, with / or \\ between names. A value
is judged by its name and by where it sits (the canonical path of names the hive itself holds, never the
spelling the caller typed) and never by its type, so a value of an odd type under a secret's name or place is
withheld too; only a DWORD or QWORD is let through under a secret-sounding name. A secret inside a value that
does not look like one (a command line with a password in it) is NOT recognised and comes back whole.
"""
import collections
import datetime
import json
import os
import re
import stat
import sys
import tempfile
from pathlib import Path

PARSER = "regkv/3"
MAX_DEPTH = 128
FILETIME_EPOCH = datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc)
SENSITIVE_NAME = re.compile(r"passw(or)?d|pwd|secret|token|credential|api_?key|private_?key", re.I)
NUMBER_TYPES = ("REG_DWORD", "REG_DWORD_BIG_ENDIAN", "REG_QWORD")
INLINE_NODES = 2000
MAX_NODES = 1_000_000

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


def ft_to_iso(ft):
    """A FILETIME (100 ns since 1601-01-01 UTC) as ISO 8601 UTC with seven fractional digits, by integer arithmetic."""
    try:
        whole, ticks = divmod(int(ft), 10_000_000)
        return (FILETIME_EPOCH + datetime.timedelta(seconds=whole)).strftime("%Y-%m-%dT%H:%M:%S") + ".%07dZ" % ticks
    except (TypeError, ValueError, OverflowError):
        return None


class KeyMissing(Exception):
    """The key asked for is not in the hive: what was found, what is missing, and the names that are there."""

    def __init__(self, found, missing, there):
        super().__init__(missing)
        self.found, self.missing, self.there = found, missing, there


def split_path(path):
    return [p for p in str(path).replace("/", "\\").split("\\") if p]


def resolve(hive, path):
    """The key at `path`, from the hive's root, and the names of it as the hive itself holds them. regipy's get_key
    takes the first part of a path that does not start with a backslash for the root's own name and drops it, so
    the path is walked here: the root's name is dropped when the caller gave it, / is taken for \\, and a part is
    matched without regard to case. The canonical names are what a value is judged by (a place such as
    Policy\\Secrets is the same place however the caller spelled it)."""
    parts = split_path(path)
    if parts and parts[0].lower() == (hive.root.name or "").lower():
        parts = parts[1:]
    node, names = hive.root, []
    for part in parts:
        kids = list(node.iter_subkeys() or [])
        match = next((kid for kid in kids if kid.name.lower() == part.lower()), None)
        if match is None:
            raise KeyMissing("\\" + "\\".join(names), part, sorted(kid.name for kid in kids))
        node, names = match, names + [match.name]
    return node, names


def hive_kind(hive):
    kind = getattr(hive, "hive_type", None)
    return str(kind).lower() if kind else None


SAM_USER_KEY = re.compile(r"\\domains\\account\\users\\[0-9a-f]{8}\\$")
CACHED_LOGON = re.compile(r"^NL\$", re.I)
SECRET_PLACES = ("\\policy\\secrets\\", "\\policy\\poleklist\\", "\\policy\\polsecretencryptionkey\\")


def sensitive_value(names, name, vtype):
    """Whether this value is registry material that can be a secret (see the module note). Decided by the value's
    name and the key's place in the hive (its canonical names), never by the value's type and never by what the hive
    file calls itself. The one thing a type buys is that a DWORD or QWORD is not text and is let through under a
    secret-sounding name; a place withholds every value in it."""
    name = name or ""
    if (SENSITIVE_NAME.search(name) or CACHED_LOGON.match(name)) and vtype not in NUMBER_TYPES:
        return True
    path = "\\" + "\\".join(names).lower() + "\\"
    if any(place in path for place in SECRET_PLACES):
        return True
    return bool(SAM_USER_KEY.search(path)) and name.lower() == "v"


def read_values(k, shown, names, withheld, problems):
    """Every value of key `k`, whole: the value as regipy decodes it (bytes as hex), its type and its length."""
    values, types, lengths, corrupted = {}, {}, {}, []
    read = 0
    try:
        # trim_values=False: the default cuts a binary value to 128 bytes and a string to 256 characters.
        for v in k.iter_values(trim_values=False):
            read += 1
            val = v.value
            vtype = str(v.value_type)
            if isinstance(val, (bytes, bytearray)):
                length, unit = len(val), "bytes"
                val = bytes(val).hex()
            elif isinstance(val, str):
                length, unit = len(val), "characters"
            elif isinstance(val, list):
                length, unit = len(val), "strings"
            else:
                length, unit = None, None
            if sensitive_value(names, v.name, vtype):
                withheld.append({"key": shown, "name": v.name, "type": vtype, "length": length})
                val = "[withheld: %d %s]" % (length, unit) if length is not None else "[withheld]"
            name = v.name
            n = 2
            while name in values:
                name = "%s (%d)" % (v.name, n)
                n += 1
            if name != v.name:
                problems.append({"where": shown, "what": "values", "error": "the key holds more than one value named %r; the later ones are listed as %r" % (v.name, name)})
            values[name] = val
            types[name] = vtype
            lengths[name] = length
            if getattr(v, "is_corrupted", False):
                corrupted.append(name)
    except Exception as exc:                                  # a damaged value list: what was read is kept, the rest is named
        problems.append({"where": shown, "what": "values", "error": "%s: %s" % (type(exc).__name__, exc)})
    declared = getattr(k, "values_count", None)
    if isinstance(declared, int) and not isinstance(declared, bool) and declared != read:
        problems.append({"where": shown, "what": "values",
                         "error": "the key declares %d values and %d were read (regipy stops at a value record it cannot parse and skips one of a type it does not know)" % (declared, read)})
    return values, types, lengths, corrupted


def list_id(node):
    """What names a key's subkey list: two keys that share it are a cycle or a damaged hive, never two lists."""
    header = getattr(node, "header", None)
    return getattr(header, "subkeys_list_offset", None)


def dump(hive_path, key, recurse=False, depth=2, limit=500, max_nodes=MAX_NODES):
    from regipy.registry import RegistryHive
    h = RegistryHive(hive_path)
    k, names = resolve(h, key)
    shown = "\\".join(names)
    problems, withheld = [], []
    out = {"key": key, "values": {}, "subkeys": []}
    values, types, lengths, corrupted = read_values(k, shown, names, withheld, problems)
    out["values"], out["value_types"], out["value_lengths"] = values, types, lengths
    if corrupted:
        out["corrupted_values"] = corrupted
    hdr = getattr(k, "header", None)
    if hdr is not None:
        out["last_modified"] = ft_to_iso(hdr.last_modified)
        out["last_modified_filetime"] = str(hdr.last_modified)
    page_key = [hive_path, key, depth, bool(recurse)]
    nodes = LosslessPage("regkv", [hive_path, key, depth], limit)
    every = LosslessPage("regkv-subkeys", page_key, INLINE_NODES)
    stopped = LosslessPage("regkv-stopped", [hive_path, key, depth], 50)
    seen = 0
    tree_complete = True
    visited = set()
    if list_id(k) is not None and k.subkey_count:
        visited.add(list_id(k))
    # Breadth first from the key asked for: (a key's node, the list its entries go in, its path, its depth).
    queue = collections.deque([(k, out["subkeys"], shown, 0)])
    while queue:
        node, target, path, d = queue.popleft()
        try:
            children = list(node.iter_subkeys() or [])
        except Exception as exc:
            problems.append({"where": path, "what": "subkeys", "error": "%s: %s" % (type(exc).__name__, exc)})
            stopped.add({"path": path, "reason": "its subkeys could not be read", "error": "%s: %s" % (type(exc).__name__, exc)})
            continue
        for s in children:
            seen += 1
            entry = {"name": s.name, "subkeys": s.subkey_count, "values": s.values_count}
            sh = getattr(s, "header", None)
            if sh is not None:
                entry["last_modified"] = ft_to_iso(sh.last_modified)
                entry["last_modified_filetime"] = str(sh.last_modified)
            child_path = (path + "\\" + s.name) if path else s.name
            # Every key listed goes to the paging block, so that what the inline list leaves out is in a file the answer names.
            every.add({"path": child_path, "depth": d + 1, "subkeys": s.subkey_count, "values": s.values_count,
                       "last_modified": entry.get("last_modified"), "last_modified_filetime": entry.get("last_modified_filetime")})
            if seen <= INLINE_NODES:
                target.append(entry)
            else:
                tree_complete = False
            if recurse:
                nodes.add({"path": child_path, "depth": d + 1, "subkeys": s.subkey_count, "values": s.values_count,
                           "last_modified": entry.get("last_modified"), "last_modified_filetime": entry.get("last_modified_filetime")})
            if recurse and s.subkey_count:
                lid = list_id(s)
                if d >= depth:
                    stopped.add({"path": child_path, "reason": "depth limit (%d)" % depth, "subkeys": s.subkey_count})
                elif seen >= max_nodes:
                    stopped.add({"path": child_path, "reason": "node limit (%d)" % max_nodes, "subkeys": s.subkey_count})
                elif lid is not None and lid in visited:
                    problems.append({"where": child_path, "what": "subkeys",
                                     "error": "its subkey list (offset %s) was already reached: a cycle, or a list two keys share; it is not entered again" % lid})
                    stopped.add({"path": child_path, "reason": "its subkey list was already reached (a cycle or a shared list)", "subkeys": s.subkey_count})
                else:
                    if lid is not None:
                        visited.add(lid)
                    sub = []
                    if seen <= INLINE_NODES:
                        entry["subkey_list"] = sub
                    queue.append((s, sub, child_path, d + 1))
    out["tree_complete"] = tree_complete
    out["nodes_listed"] = seen
    every_page = every.finish()
    if every_page.get("all_results"):
        out["all_subkeys"] = every_page["all_results"]
        out["all_subkeys_note"] = "every key listed, with its path: the inline subkeys and subkey_list hold the first %d" % INLINE_NODES
    stopped_page = stopped.finish()
    out["stopped_branches"] = stopped.page
    out["stopped_branch_count"] = stopped_page["matched"]
    if stopped_page.get("all_results"):
        out["all_stopped_branches"] = stopped_page["all_results"]
    node_page = nodes.finish()
    if recurse:
        out["nodes"] = nodes.page
        out["node_count"] = node_page["matched"]
        if node_page.get("all_results"):
            out["all_nodes"] = node_page["all_results"]
    out["problems"] = problems
    out["sensitive_values_withheld"] = withheld
    header = h.header
    out["hive_dirty"] = header.primary_sequence_num != header.secondary_sequence_num
    out["hive_sequence_numbers"] = [header.primary_sequence_num, header.secondary_sequence_num]
    out["transaction_logs_beside_hive"] = [hive_path + s for s in (".LOG1", ".LOG2", ".LOG") if os.path.isfile(hive_path + s)]
    out["transaction_logs_replayed"] = False
    out["hive_type"] = hive_kind(h)
    return out


def refuse(message, **extra):
    print(json.dumps({"ok": False, "error": message, **extra}))
    sys.exit(1)


def main():
    raw = sys.stdin.read()
    if not raw.strip():
        print(json.dumps({'error': 'no JSON input'})); sys.exit(1)
    try:
        args = json.loads(raw)
    except ValueError as exc:
        refuse("arguments are not valid JSON", reason=str(exc))
    if not isinstance(args, dict):
        refuse("the arguments are one JSON object")
    hive = args.get('hive'); key = args.get('key')
    if not isinstance(hive, str) or not hive or not isinstance(key, str):
        refuse('hive and key are required, both text')
    try:
        mode = os.stat(hive).st_mode
    except OSError:
        refuse('no such hive', hive=hive)
    if not stat.S_ISREG(mode):
        # A named pipe or a device would be opened and waited on: it is not read.
        refuse('the hive is not a regular file, so it was not opened', hive=hive, not_attempted=1)
    recurse = bool(args.get('recurse', False))
    depth = args.get('depth', 2)
    limit = args.get('limit', 500)
    max_nodes = args.get('max_nodes', MAX_NODES)
    for name, v, low, high in (("depth", depth, 0, MAX_DEPTH), ("limit", limit, 1, None), ("max_nodes", max_nodes, 1, None)):
        if isinstance(v, bool) or not isinstance(v, int) or v < low or (high is not None and v > high):
            refuse("%s must be a whole number from %d%s" % (name, low, " to %d" % high if high is not None else " up"), name=v)
    try:
        import regipy.registry  # noqa: F401  (dump() imports what it uses; this is where a missing library is said)
    except ImportError as exc:
        refuse("regipy is not installed: python3 -m pip install regipy", reason=str(exc))
    try:
        out = dump(hive, key, recurse, depth, limit, max_nodes)
    except KeyMissing as gone:
        print(json.dumps({'ok': False, 'error': 'key not found', 'key': key, 'deepest_found': gone.found,
                          'missing': gone.missing, 'subkeys_there': gone.there}, indent=1)); sys.exit(1)
    except Exception as exc:                                  # not a hive, or one regipy cannot open
        refuse("could not read the hive", hive=hive, reason="%s: %s" % (type(exc).__name__, exc))
    try:
        from importlib.metadata import version
        regipy_version = version("regipy")
    except Exception:
        regipy_version = None
    out = {"parser": PARSER, "regipy_version": regipy_version, "hive": hive,
           "status": "partial" if out["problems"] or out["stopped_branch_count"] or not out["tree_complete"] else "complete", **out}
    print(json.dumps(out, indent=1, default=str))


if __name__ == '__main__':
    try:
        main()
    except SystemExit:
        raise
    except Exception as exc:                                  # whatever hostile input does, the answer is JSON
        print(json.dumps({"ok": False, "error": "the read failed", "reason": "%s: %s" % (type(exc).__name__, exc)}))
        sys.exit(1)
