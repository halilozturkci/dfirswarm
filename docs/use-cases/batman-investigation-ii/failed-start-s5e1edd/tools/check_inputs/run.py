#!/usr/bin/env python3
"""Diff inputs/ against inputs.json. Always-OK hashing is a false negative."""
import hashlib
import json
import os
import sys

MANIFEST = "inputs.json"
if not os.path.isfile(MANIFEST):
    print(json.dumps({"status": "FAIL", "error": "inputs.json not found"}))
    sys.exit(1)
try:
    man = json.load(open(MANIFEST, encoding="utf-8"))
except json.JSONDecodeError as err:
    print(json.dumps({"status": "FAIL", "error": f"inputs.json is not JSON: {err}"}))
    sys.exit(1)
files = man.get("files") if isinstance(man, dict) else None
if not isinstance(files, list):
    print(json.dumps({"status": "FAIL", "error": "inputs.json has no files list"}))
    sys.exit(1)

def sha256_file(path):
    # In chunks: an input can be tens of gigabytes, and reading one whole is
    # both a MemoryError in a small VM and against the ground rules.
    digest = hashlib.sha256()
    size = 0
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            digest.update(chunk)
            size += len(chunk)
    return digest.hexdigest(), size


modified = []
missing = []
known = {}
for entry in files:
    if not isinstance(entry, dict) or not isinstance(entry.get("path"), str):
        continue
    rel = entry["path"]
    known[rel] = entry
    # A link inside the evidence is recorded as a link, and checked as one:
    # its target, never followed.
    if isinstance(entry.get("link"), str):
        if not os.path.islink(rel):
            missing.append(rel)
        elif os.readlink(rel) != entry["link"]:
            modified.append(rel)
        continue
    if os.path.islink(rel):
        modified.append(rel)
        continue
    if not os.path.isfile(rel):
        missing.append(rel)
        continue
    digest, size = sha256_file(rel)
    want_hash = entry.get("sha256")
    want_bytes = entry.get("bytes")
    if want_hash and digest != want_hash:
        modified.append(rel)
    elif want_bytes is not None and int(want_bytes) != size:
        modified.append(rel)

# Several sets, each at inputs/<name>/: one held in place is a link there,
# walked through as the set it is.
sets = [s.get("name") for s in (man.get("sets") or []) if isinstance(s, dict) and isinstance(s.get("name"), str)]

added = []
if os.path.isdir("inputs"):
    top = os.path.realpath("inputs")
    held = [n for n in sets if "/" not in n and os.path.islink(os.path.join(top, n))]
    for walked, under in [(top, "inputs/")] + [(os.path.realpath(os.path.join(top, n)), "inputs/" + n + "/") for n in held]:
        for root, dirs, names in os.walk(walked):
            # A directory link is a name of its own, not a place to walk into.
            for name in names + [d for d in dirs if os.path.islink(os.path.join(root, d)) and not (root == top and d in held)]:
                rel = under + os.path.relpath(os.path.join(root, name), walked).replace("\\", "/")
                if rel not in known:
                    added.append(rel)

ok = not modified and not missing and not added
print(json.dumps({
    "status": "OK" if ok else "FAIL",
    "ok": ok,
    "modified": modified,
    "missing": missing,
    "added": added,
    "checked": len(known),
}))
sys.exit(0 if ok else 1)
