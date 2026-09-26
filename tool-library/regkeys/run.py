import sys, json, datetime
from regipy.registry import RegistryHive
from regipy.exceptions import RegistryKeyNotFoundException

def ft(ft100ns):
    if not ft100ns:
        return None
    return datetime.datetime.fromtimestamp(ft100ns/10**7 - 11644473600, datetime.timezone.utc).isoformat()

TEXT_TYPES = ("REG_SZ", "REG_EXPAND_SZ", "REG_LINK")


def render(value, value_type):
    """Render a raw value by the type the registry itself gives it.

    Every bytes value used to be decoded as utf-16-le with errors="replace",
    which turned REG_BINARY blobs — a ShimCache entry, a UserAssist record, a
    cached credential — into mojibake that looked like text and could be
    quoted into a report. "replace" never raises, so the hex fallback below
    it was unreachable. Binary now comes back as hex, which is what `regkv`
    and `reg_hive_query` already report for the same value: one hive, one
    answer. Returns (value, how it was rendered).
    """
    if not isinstance(value, (bytes, bytearray)):
        return value, None
    value = bytes(value)
    if value_type in TEXT_TYPES:
        try:
            return value.decode("utf-16-le").rstrip("\x00"), "utf-16-le"
        except UnicodeDecodeError:
            return value.hex(), "hex"
    if value_type == "REG_MULTI_SZ":
        try:
            text = value.decode("utf-16-le")
        except UnicodeDecodeError:
            return value.hex(), "hex"
        return [part for part in text.split("\x00") if part], "utf-16-le"
    return value.hex(), "hex"


def node(key):
    out = {
        "name": key.name,
        "last_modified": ft(getattr(key.header, "last_modified", None)),
        "values": [],
        "subkeys": [],
    }
    for v in key.iter_values():
        val, encoding = render(v.value, v.value_type)
        entry = {"name": v.name, "value_type": v.value_type, "value": val}
        if encoding is not None:
            entry["encoding"] = encoding
        out["values"].append(entry)
    return out

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
    data = json.load(sys.stdin)
    hive_path = data["hive"]
    key_path = data.get("key") or ""
    recurse = int(data.get("recurse", 0))
    limit = data.get("limit")
    if limit is not None:
        print(json.dumps({
            "ok": False,
            "error": "limit would cut the registry tree and is not supported",
            "hint": "omit limit; narrow key or recurse instead",
        }))
        return 1
    h = RegistryHive(hive_path)
    if key_path:
        try:
            k = rooted_key(h, key_path)
        except RegistryKeyNotFoundException:
            print(json.dumps({"ok": False, "error": "key not found", "key": key_path, **nearest_key(h, key_path)}))
            return 1
    else:
        k = h.root
    result = node(k)
    def walk(k, depth, parent):
        subs = list(k.iter_subkeys())
        for sk in subs:
            child = node(sk)
            parent["subkeys"].append(child)
            if depth < recurse:
                walk(sk, depth + 1, child)
    walk(k, 0, result)
    print(json.dumps(result, indent=2))
    return 0

if __name__ == "__main__":
    sys.exit(main())
