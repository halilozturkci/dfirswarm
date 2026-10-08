#!/usr/bin/env python3
"""Diff inputs/ against inputs.json. Always-OK hashing is a false negative.

The manifest is validated whole before any file is hashed: every entry must be an object with a
path (its `path_b64` when the name is not UTF-8), no path may appear twice, a regular file needs
its size (`bytes`) and a sha256, a link its target (`link`), a device, pipe or socket its kind
(`special`). An entry that fails is reported as malformed, never skipped, and an entry with no
sha256 is `digest_missing`: it could be checked by size alone, which is not a verification, so the
run does not pass. A file that cannot be opened is `unreadable`, a file not reached before the
time budget is `not_checked`; neither is a pass. Every file's result is written to a receipts
file as it is checked, so a long hash leaves a record even if the run is cut short.

A pass says: every file the manifest lists is here and has the bytes and digest it lists, and
nothing else is under inputs/. It does not say the evidence is authentic, or complete, or that the
baseline (the manifest) was right when it was made. This is the pack tool's receipt; the harness's
own `inputs_check` event is written by the harness at completion, not by this tool.

Exit 0 only when every check passed.
"""
import base64
import hashlib
import json
import os
import re
import stat
import sys
import tempfile
import time
from pathlib import Path

TOOL = {"name": "check_inputs", "version": 4}
MANIFEST = "inputs.json"
SHA256 = re.compile(r"^[0-9a-f]{64}$")
SPECIALS = {"fifo": stat.S_ISFIFO, "socket": stat.S_ISSOCK, "char": stat.S_ISCHR, "block": stat.S_ISBLK}
DEFAULT_SECONDS = 1500
SECONDS_MAX = 1700                     # the tool's own time limit is 1800 seconds: a budget beyond it would be killed, not reported
LISTED = 200


def done(obj, code):
    print(json.dumps(obj))
    sys.exit(code)


def name_of(entry, key):
    """A name as bytes on disk: key_b64 when the manifest kept the raw bytes, else the text."""
    raw_b64 = entry.get(key + "_b64")
    if raw_b64 is not None:
        try:
            return os.fsdecode(base64.b64decode(raw_b64, validate=True))
        except (ValueError, TypeError):
            return None
    value = entry.get(key)
    return value if isinstance(value, str) else None


def sha256_file(path, deadline):
    # In chunks: an input can be tens of gigabytes, and reading one whole is
    # both a MemoryError in a small VM and against the ground rules.
    digest = hashlib.sha256()
    size = 0
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            digest.update(chunk)
            size += len(chunk)
            if time.monotonic() > deadline:
                return None, size
    return digest.hexdigest(), size


class Receipts:
    """One new file per run, written row by row in place: a run that is killed leaves the rows it had.

    The name carries the time and the process, so a second check in the same run directory does not
    replace the first one's record; the file is created exclusively and never opened over.
    """

    def __init__(self):
        stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
        name = "check_inputs-receipts-%s-%d.jsonl" % (stamp, os.getpid())
        job, out = os.environ.get("JOB_ID"), os.environ.get("OUT")
        if job and out:
            self.path = Path(out) / "tool-output" / name
            self.shown = "store/jobs/%s/out/tool-output/%s" % (re.sub(r"[^A-Za-z0-9_.-]", "_", job), name)
        else:
            agent = re.sub(r"[^A-Za-z0-9_.-]", "_", os.environ.get("AGENT_ID") or "tool")
            self.path = Path("work") / agent / "tool-output" / name
            self.shown = str(self.path)
        self.fh, self.error, self.count, self.created = None, None, 0, False
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
            self.fh = os.fdopen(fd, "w", encoding="ascii")
            self.created = True
        except OSError as exc:
            self.error = "the receipts could not be written (%s: %s)" % (self.path.parent, exc.strerror or exc)

    def add(self, row):
        if self.fh:
            try:
                self.fh.write(json.dumps(row) + "\n")       # ASCII escapes: a name that is not UTF-8 is written, not lost
                self.fh.flush()                                # a receipt is on disk before the next file is read
                self.count += 1
            except OSError as exc:
                self.error = "the receipts stopped being written after %d rows (%s)" % (self.count, exc.strerror or exc)
                self.fh = None

    def finish(self):
        if self.fh:
            try:
                self.fh.flush()
                os.fsync(self.fh.fileno())
                self.fh.close()
            except OSError as exc:
                self.error = "the receipts were not synced (%s)" % (exc.strerror or exc)


if not os.path.isfile(MANIFEST):
    done({"status": "FAIL", "ok": False, "error": "inputs.json not found", "tool": TOOL}, 1)
try:
    args = json.load(sys.stdin) if not sys.stdin.isatty() else {}
except ValueError:
    args = {}
budget = args.get("max_seconds", DEFAULT_SECONDS) if isinstance(args, dict) else DEFAULT_SECONDS
if not isinstance(budget, int) or isinstance(budget, bool) or not 1 <= budget <= SECONDS_MAX:
    done({"status": "FAIL", "ok": False, "error": "max_seconds is a whole number from 1 to %d" % SECONDS_MAX, "tool": TOOL}, 1)
try:
    man = json.load(open(MANIFEST, encoding="utf-8"))
except json.JSONDecodeError as err:
    done({"status": "FAIL", "ok": False, "error": f"inputs.json is not JSON: {err}", "tool": TOOL}, 1)
files = man.get("files") if isinstance(man, dict) else None
if not isinstance(files, list):
    done({"status": "FAIL", "ok": False, "error": "inputs.json has no files list", "tool": TOOL}, 1)

# --- the whole manifest first -------------------------------------------------------------------
malformed, duplicates, digest_missing = [], [], []
entries, known = [], {}
for i, entry in enumerate(files):
    if not isinstance(entry, dict):
        malformed.append({"index": i, "why": "not an object"})
        continue
    rel = name_of(entry, "path")
    if rel is None:
        malformed.append({"index": i, "why": "no readable path (path, or a path_b64 that is not base64)"})
        continue
    # Where the entry really points: `inputs/../x`, `inputs//a/./b` and `/etc/passwd` are named by their normal form, and a
    # place that is not under inputs/ is not the evidence's: it is not hashed, and it is reported as malformed.
    orig = rel
    rel = os.path.normpath(rel) if rel else rel
    if not rel or os.path.isabs(rel) or rel == "inputs" or not rel.startswith("inputs" + os.sep) or ".." in rel.split(os.sep):
        malformed.append({"index": i, "path": orig, "why": "the path is outside inputs/ (as written, or once ../ and ./ are resolved: %s)" % rel})
        continue
    if rel in known:
        duplicates.append(rel)
        continue
    kind = "link" if "link" in entry or "link_b64" in entry else "special" if "special" in entry else "file"
    why = None
    if kind == "link":
        if name_of(entry, "link") is None:
            why = "a link with no readable target"
    elif kind == "special":
        if entry.get("special") not in SPECIALS:
            why = "special is not one of %s" % ", ".join(sorted(SPECIALS))
    else:
        if not isinstance(entry.get("bytes"), int) or isinstance(entry.get("bytes"), bool) or entry["bytes"] < 0:
            why = "a regular file with no valid size (bytes)"
        elif entry.get("sha256") in (None, ""):
            digest_missing.append(rel)
        elif not isinstance(entry.get("sha256"), str) or not SHA256.match(entry["sha256"]):
            why = "sha256 is not 64 hexadecimal digits"
    if why:
        malformed.append({"index": i, "path": rel, "why": why})
        known[rel] = entry
        continue
    known[rel] = entry
    entries.append((rel, kind, entry))

# --- each entry against the disk ----------------------------------------------------------------
receipts = Receipts()
deadline = time.monotonic() + budget
modified, missing, unreadable, not_checked = [], [], [], []
bytes_hashed = 0
for rel, kind, entry in entries:
    row = {"path": rel, "kind": kind}
    try:
        if kind == "link":
            want = name_of(entry, "link")
            if not os.path.islink(rel):
                missing.append(rel)
                row["result"] = "missing"
            elif os.readlink(rel) != want:
                modified.append(rel)
                row["result"] = "modified: the link target differs"
            else:
                row["result"] = "ok"
        elif kind == "special":
            if not os.path.lexists(rel):
                missing.append(rel)
                row["result"] = "missing"
            elif not SPECIALS[entry["special"]](os.lstat(rel).st_mode):
                modified.append(rel)
                row["result"] = "modified: not a %s any more" % entry["special"]
            else:
                row["result"] = "ok"
        elif os.path.islink(rel):
            modified.append(rel)
            row["result"] = "modified: a link where a file was recorded"
        elif not os.path.isfile(rel):
            missing.append(rel)
            row["result"] = "missing"
        elif time.monotonic() > deadline:
            not_checked.append(rel)
            row["result"] = "not checked: the time budget was used"
        else:
            size_on_disk = os.path.getsize(rel)
            row["bytes"] = size_on_disk
            if entry.get("bytes") is not None and size_on_disk != entry["bytes"]:
                # A different size is a different file; there is no need to read it to say so.
                modified.append(rel)
                row["result"] = "modified: the size differs (%d, recorded %d)" % (size_on_disk, entry["bytes"])
            elif rel in digest_missing:
                row["result"] = "digest missing: the size matches, and that is all that was checked"
            else:
                digest, size = sha256_file(rel, deadline)
                bytes_hashed += size
                if digest is None:
                    not_checked.append(rel)
                    row["result"] = "not checked: the time budget ran out after %d bytes" % size
                elif digest != entry["sha256"]:
                    modified.append(rel)
                    row["sha256"] = digest
                    row["result"] = "modified: the sha256 differs"
                elif size != size_on_disk:
                    modified.append(rel)
                    row["result"] = "modified: the size changed while it was read"
                else:
                    row["sha256"] = digest
                    row["result"] = "ok"
    except OSError as exc:
        unreadable.append({"path": rel, "why": exc.strerror or str(exc)})
        row["result"] = "unreadable: %s" % (exc.strerror or exc)
    receipts.add(row)
receipts.finish()

# Several sets, each at inputs/<name>/: one held in place is a link there,
# walked through as the set it is.
sets = [s.get("name") for s in (man.get("sets") or []) if isinstance(s, dict) and isinstance(s.get("name"), str)]

added = []
if os.path.isdir("inputs"):
    top = os.path.realpath("inputs")
    held = [n for n in sets if "/" not in n and os.path.islink(os.path.join(top, n))]
    for walked, under in [(top, "inputs/")] + [(os.path.realpath(os.path.join(top, n)), "inputs/" + n + "/") for n in held]:
        def unreadable_dir(exc, walked=walked, under=under):
            where = os.path.relpath(os.fsdecode(exc.filename or walked), walked).replace("\\", "/")
            unreadable.append({"path": under if where == "." else under + where, "why": "a directory under inputs/ could not be listed: %s" % (exc.strerror or exc)})
        for root, dirs, names in os.walk(walked, onerror=unreadable_dir):
            # A directory link is a name of its own, not a place to walk into.
            for name in names + [d for d in dirs if os.path.islink(os.path.join(root, d)) and not (root == top and d in held)]:
                rel = under + os.path.relpath(os.path.join(root, name), walked).replace("\\", "/")
                if rel not in known:
                    added.append(rel)

ok = not (modified or missing or added or malformed or duplicates or digest_missing or unreadable or not_checked)
result = {
    "tool": TOOL,
    "status": "OK" if ok else "FAIL",
    "ok": ok,
    "modified": modified,
    "missing": missing,
    "added": added,
    "checked": len(known),
    "malformed": malformed[:LISTED],
    "duplicates": duplicates[:LISTED],
    "digest_missing": digest_missing[:LISTED],
    "unreadable": unreadable[:LISTED],
    "not_checked": not_checked[:LISTED],
    "bytes_hashed": bytes_hashed,
    "receipts_file": receipts.shown if receipts.created else None,
    "receipts": receipts.count,
    "does_not_show": "that the evidence is authentic or complete, or that the manifest was right when it was made: a pass is agreement with the baseline",
}
if receipts.error:
    result["receipts_error"] = receipts.error
for name in ("malformed", "duplicates", "digest_missing", "unreadable", "not_checked"):
    total = len(locals()[name])
    if total > LISTED:
        result[name + "_total"] = total
        result[name + "_note"] = "the first %d are listed; every file's result is in the receipts file" % LISTED
done(result, 0 if ok else 1)
