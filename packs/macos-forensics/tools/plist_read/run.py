#!/usr/bin/env python3
"""Read XML and binary property lists and return JSON-safe values, never a secret.

Most system plists on a modern macOS are binary. A grep over one finds nothing
while the value sits there in plain sight, and `strings` gives keys without
values and values without keys, which is how an answer gets assembled out of two
unrelated halves. plistlib in the standard library reads both encodings.

Dates are the other trap. A plist date is a real type holding seconds since
2001-01-01 UTC, the Apple epoch, and a reader that treats the number as Unix
time is off by thirty-one years. Those are converted here, and every converted
value says it is UTC (plistlib's conversion: microsecond resolution; the raw
float is not kept).

THE SECRET-SAFE OUTPUT PATTERN (docs/packs.md, "Secrets and sensitive output").
An account plist under /private/var/db/dslocal/nodes/Default/users/ holds a
password verifier (ShadowHashData), Kerberos keys and sometimes a password hint;
other plists hold tokens and passwords under keys named for them. This tool is
the macOS pack's copy of the pattern recovery_key_scan introduced:

  1. The answer carries presence, kind, location (file and key path) and length.
     A binary value is `{_binary_bytes, _kind, finding_id}`: no digest of it, no
     base64 of it, no head of it, however short (it used to carry all three, and
     `max_blob: 0` still carried the digest). A value under a key whose name marks
     it secret-bearing (a verifier, Kerberos keys, a password, a passphrase, a
     secret, a token, a credential, a private key, a hint) is withheld the same
     way, whatever its type, at any depth, and also when `key` selects it.
  2. A value is written only on `write_values: true`, only when the tool runs as
     a job (JOB_ID and OUT are set), and only to $OUT/plist-values.jsonl: JSON
     Lines, mode 0600, created exclusively before anything is read, one row per
     binary or withheld value, with the answer's finding_id, the real file and
     key path, and the value (a binary value as base64, up to `max_blob` bytes,
     with its whole length beside it). The skill that sends the agent here says
     the job runs with `secret_output: true`. Outside a job the request is
     refused and nothing is written.
  3. A secret is never on a command line: this tool takes a path and flags only.
  4. Strings and numbers under keys that are not named for a secret are printed
     as they are. A plist can hold a secret under an innocent name; that is why
     an account plist is read as a job with `secret_output: true`, or by `key`
     selection of the keys the question needs.

A tool that fails loudly: a file it cannot parse, one over `max_file_bytes` or
`max_nodes`, a tree deeper than `max_depth`, a link not followed and a file not
attempted before `max_seconds` are each counted and named, per file; one bad file
never stops the sweep and never becomes an empty result.
"""
import base64
import datetime
import hashlib
import json
import math
import os
import plistlib
import re
import stat
import sys
import tempfile
import time
from pathlib import Path

PARSER = "plist_read/3"
SECRET_VALUES_NAME = "plist-values.jsonl"
DEFAULT_MAX_BLOB = 4096
DEFAULT_MAX_FILE_BYTES = 32 << 20
DEFAULT_MAX_NODES = 200000
DEFAULT_MAX_DEPTH = 100
DEFAULT_MAX_SECONDS = 90.0
DEFAULT_INLINE_BYTES = 1 << 20
FIRST_FAILURES = 20

# A key whose name marks what it holds as secret-bearing. Matched as a pattern on
# the name at every depth, and on every component of a `key` path. A false positive
# costs a locator instead of a value (the value is in the values file, in a job); a
# false negative would print a secret, so the list leans broad.
SECRET_KEY = re.compile(
    r"shadowhash|kerberoskeys|passw|passphrase|secret|token|credential|api[_-]?key|private[_-]?key|verifier|^hint$",
    re.I,
)


def fail(message, **extra):
    print(json.dumps({"error": message, **extra}))
    raise SystemExit(1)


def resolve_output(out, what="output"):
    """Where `out` really lands, as a path under the run directory; a place
    outside it, the run directory itself, or anything under inputs/ is refused.

    A string check is not enough: `work/../inputs/x`, an absolute path and a
    symlink that points out all name a place the tool must not write, and none
    of them starts with "inputs/". Resolving first and comparing directories
    is what actually holds, and the read-only inputs are the one place
    extracted bytes must never appear -- a later integrity check would report
    the evidence as modified. In a job $OUT is inside the run directory.
    """
    root = Path.cwd().resolve()
    dest = (root / out).resolve() if not Path(out).is_absolute() else Path(out).resolve()
    if dest == root or root not in dest.parents:
        fail("%s must stay inside the run directory" % what, **{what: str(out)})
    inputs = root / "inputs"
    if dest == inputs or inputs in dest.parents:
        fail("%s cannot be under inputs/" % what, **{what: str(out)})
    return str(dest.relative_to(root))


def describe(exc):
    return "%s: %s" % (type(exc).__name__, exc)


# Lossless paging (the same in every library tool that pages): the page an
# agent reads stays small, bounded by rows and by bytes, and when there are more
# rows the whole result is written as JSON Lines under work/<agent>/tool-output
# (in a job, $OUT/tool-output) and named. The file name is a digest of the page's
# key (a path), never of a value. Rows are written with ensure_ascii on: a path
# the filesystem gave as bytes that are not UTF-8 reaches Python as lone
# surrogates, which a UTF-8 file cannot hold and an escape can. A rerun that
# would replace a larger earlier file of the same name writes a new name and says
# which earlier file it kept.
class LosslessPage:
    def __init__(self, tool, key, limit, byte_limit=None):
        if isinstance(limit, bool) or not isinstance(limit, int) or limit < 1:
            raise ValueError("limit must be a positive integer")
        self.tool = re.sub(r"[^A-Za-z0-9_.-]", "_", tool)
        self.limit = limit
        self.byte_limit = byte_limit
        self.page = []
        self.page_bytes = 0
        self.full = False
        self.bytes_bound_hit = False
        self.total = 0
        self._out = None
        self._tmp = None
        digest = hashlib.sha256(json.dumps(key, sort_keys=True, default=str).encode("utf-8")).hexdigest()[:16]
        name = "%s-%s.jsonl" % (self.tool, digest)
        job, out = os.environ.get("JOB_ID"), os.environ.get("OUT")
        if job and out:
            # In a job only $OUT is written, and it is sealed as the job's
            # output: the whole result is cited from there.
            self.path = Path(out) / "tool-output" / name
            self.shown = "store/jobs/%s/out/tool-output/%s" % (re.sub(r"[^A-Za-z0-9_.-]", "_", job), name)
        else:
            agent = re.sub(r"[^A-Za-z0-9_.-]", "_", os.environ.get("AGENT_ID") or "tool")
            self.path = Path("work") / agent / "tool-output" / name
            self.shown = str(self.path)

    def _write(self, row):
        self._out.write(json.dumps(row, default=str))
        self._out.write("\n")

    def add(self, row):
        self.total += 1
        if not self.full and len(self.page) < self.limit:
            size = len(json.dumps(row, default=str)) if self.byte_limit is not None else 0
            if self.byte_limit is None or self.page_bytes + size <= self.byte_limit:
                self.page.append(row)
                self.page_bytes += size
                return
            self.bytes_bound_hit = True
        # From the first row that does not fit, every later row goes to the file only: the page is a prefix.
        self.full = True
        if self._out is None:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            fd, name = tempfile.mkstemp(dir=self.path.parent, prefix=".%s-" % self.path.name)
            self._tmp = Path(name)
            self._out = os.fdopen(fd, "w", encoding="utf-8")
            for kept in self.page:
                self._write(kept)
        self._write(row)

    def finish(self):
        result = {"matched": self.total, "returned": len(self.page), "truncated": self.total > len(self.page)}
        if self.byte_limit is not None:
            result["inline_byte_limit"] = self.byte_limit
            if self.bytes_bound_hit:
                result["inline_bounded_by_bytes"] = True
        if self._out is not None:
            self._out.flush()
            os.fsync(self._out.fileno())
            self._out.close()
            target, shown = self.path, self.shown
            if target.exists() and target.stat().st_size > os.path.getsize(self._tmp):
                n = 2
                while target.with_name("%s-%d%s" % (target.stem, n, target.suffix)).exists():
                    n += 1
                target = target.with_name("%s-%d%s" % (target.stem, n, target.suffix))
                shown = self.shown.rsplit("/", 1)[0] + "/" + target.name
                result["kept_earlier_larger_result"] = self.shown
            os.replace(self._tmp, target)
            result["all_results"] = shown
            result["all_results_format"] = "JSON Lines, one complete result per line"
        return result


class SecretValuesRefused(Exception):
    pass


class SecretValues:
    """Where a value goes when, and only when, the caller asked for it.

    The pattern of recovery_key_scan (encrypted-containers), copied: call `add`
    once per binary or withheld value with its finding id, its locator and the
    value. With `enabled` false it writes nothing and `summary()` says so.
    """

    def __init__(self, enabled):
        self.enabled = enabled
        self.written = 0
        self._fh = None
        self.job = os.environ.get("JOB_ID") or ""
        self.out = os.environ.get("OUT") or ""
        self.path = None
        self.shown = None
        if not enabled:
            return
        if not (self.job and self.out):
            raise SecretValuesRefused(
                "write_values is refused outside a job: a value written here would be an ordinary "
                "file, not a sealed secret output. Run this as job_run tool=plist_read with "
                "secret_output: true, and ask again there. Nothing was written."
            )
        self.path = Path(self.out) / SECRET_VALUES_NAME
        self.shown = "store/jobs/%s/out/%s" % (re.sub(r"[^A-Za-z0-9_.-]", "_", self.job), SECRET_VALUES_NAME)
        # Created now, before anything is read: a file or a link already at that name is refused
        # by name at once (O_EXCL does not follow a link, a dangling one included), instead of
        # failing, or writing through it, after the sweep. With nothing found it stays an empty
        # file, mode 0600, and the answer says written: 0.
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            fd = os.open(str(self.path), os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        except FileExistsError:
            raise SecretValuesRefused("the values file already exists: %s" % self.path)
        except OSError as exc:
            raise SecretValuesRefused("the values file could not be created: %s (%s)" % (self.path, describe(exc)))
        self._fh = os.fdopen(fd, "w", encoding="utf-8")

    def add(self, finding_id, locator, value):
        if not self.enabled:
            return
        # ensure_ascii: a file name that is not UTF-8 is a lone surrogate to Python; an escape reads back, a raw write cannot.
        self._fh.write(json.dumps({"finding_id": finding_id, **locator, "value": value}))
        self._fh.write("\n")
        self.written += 1

    def close(self):
        if self._fh is not None:
            self._fh.flush()
            os.fsync(self._fh.fileno())
            self._fh.close()
            self._fh = None

    def summary(self):
        return {
            "requested": self.enabled,
            "written": self.written,
            "values_file": self.shown if self.enabled else None,
            "contains_secret_values": self.written > 0,
            "format": ("JSON Lines, mode 0600: finding_id, file (the real path), key_path, kind, length, "
                       "reason, value (binary as base64, up to max_blob bytes, with its whole length)")
            if self.enabled else None,
        }


class Budget(Exception):
    """A file that is over a bound: reported as skipped, with the bound and the figure."""


def kind_of(value):
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, int):
        return "integer"
    if isinstance(value, float):
        return "real"
    if isinstance(value, str):
        return "string"
    if isinstance(value, (bytes, bytearray)):
        return "data"
    if isinstance(value, datetime.datetime):
        return "date"
    if isinstance(value, dict):
        return "dict"
    if isinstance(value, (list, tuple)):
        return "array"
    if isinstance(value, plistlib.UID):
        return "uid"
    return type(value).__name__


def length_of(value):
    if isinstance(value, (dict, list, tuple, str, bytes, bytearray)):
        return len(value)
    return None


def when(value):
    stamp = value if value.tzinfo else value.replace(tzinfo=datetime.timezone.utc)
    return stamp.astimezone(datetime.timezone.utc).isoformat().replace("+00:00", "Z")


class Walk:
    """One file's conversion: a JSON-safe tree, and the locators of what was not printed."""

    def __init__(self, ids, max_nodes, max_depth, max_blob, keep):
        self.ids = ids
        self.max_nodes = max_nodes
        self.max_depth = max_depth
        self.max_blob = max_blob
        self.keep = keep          # collect the full values, for the values file
        self.nodes = 0
        self.binary = 0
        self.withheld = 0
        self.found = []           # (finding_id, locator, value) for the values file

    def count(self, depth):
        self.nodes += 1
        if self.nodes > self.max_nodes:
            raise Budget("more than max_nodes (%d) values" % self.max_nodes)
        if depth > self.max_depth:
            raise Budget("nested deeper than max_depth (%d)" % self.max_depth)

    def exported(self, value, depth):
        """The whole value as JSON, for the values file only: a binary value as base64."""
        self.count(depth)
        if isinstance(value, dict):
            return {str(k): self.exported(v, depth + 1) for k, v in value.items()}
        if isinstance(value, (list, tuple)):
            return [self.exported(v, depth + 1) for v in value]
        if isinstance(value, (bytes, bytearray)):
            head = bytes(value[:self.max_blob])
            return {"_base64": base64.b64encode(head).decode("ascii"), "_bytes": len(value),
                    "_bytes_written": len(head), "_truncated": len(value) > len(head)}
        return self.scalar(value)

    @staticmethod
    def scalar(value):
        if isinstance(value, datetime.datetime):
            return when(value)
        if isinstance(value, plistlib.UID):
            return {"_uid": value.data}
        if isinstance(value, float) and not math.isfinite(value):
            return {"_float": repr(value)}
        return value

    def locate(self, kind, length, reason, key_path, value):
        fid = self.ids()
        if self.keep:
            self.found.append((fid, {"key_path": ".".join(key_path), "kind": kind, "length": length, "reason": reason},
                               self.exported(value, 0)))
        return fid

    def convert(self, value, key_path, depth):
        self.count(depth)
        if isinstance(value, dict):
            out = {}
            for k, v in value.items():
                name = str(k)
                if SECRET_KEY.search(name):
                    out[name] = self.withhold(v, key_path + [name])
                else:
                    out[name] = self.convert(v, key_path + [name], depth + 1)
            return out
        if isinstance(value, (list, tuple)):
            return [self.convert(v, key_path + [str(i)], depth + 1) for i, v in enumerate(value)]
        if isinstance(value, (bytes, bytearray)):
            self.binary += 1
            fid = self.locate("data", len(value), "binary value", key_path, value)
            return {"_binary_bytes": len(value), "_kind": "data", "finding_id": fid}
        return self.scalar(value)

    def withhold(self, value, key_path):
        self.withheld += 1
        if isinstance(value, (bytes, bytearray)):
            self.binary += 1
        kind, length = kind_of(value), length_of(value)
        fid = self.locate(kind, length, "key name marks it secret-bearing", key_path, value)
        return {"_withheld": "the key's name marks a secret-bearing value", "_kind": kind, "_length": length,
                "finding_id": fid}


def dig(tree, path):
    cursor = tree
    for part in path.split("."):
        if isinstance(cursor, dict) and part in cursor:
            cursor = cursor[part]
        elif isinstance(cursor, list) and part.isdigit() and int(part) < len(cursor):
            cursor = cursor[int(part)]
        else:
            return None, "no key %r at that level" % part
    return cursor, None


def iso_mtime(path):
    try:
        return datetime.datetime.fromtimestamp(os.path.getmtime(path), datetime.timezone.utc).isoformat().replace("+00:00", "Z")
    except OSError:
        return None


def read_one(path, key, limits, ids, keep):
    """One file's row, and what was found in it. Never raises: a failure is the row."""
    row = {"file": path, "parser": PARSER}
    try:
        size = os.path.getsize(path)
    except OSError as exc:
        row.update(status="failed", error=describe(exc))
        return row, []
    row["bytes"] = size
    row["extracted_file_mtime"] = iso_mtime(path)
    if size > limits["max_file_bytes"]:
        row.update(status="skipped", reason="over max_file_bytes (%d): not read; raise it or read a smaller copy" % limits["max_file_bytes"])
        return row, []
    try:
        with open(path, "rb") as fh:
            head = fh.read(8)
            fh.seek(0)
            tree = plistlib.load(fh)
    except Exception as exc:  # a parser fault on hostile input is that file's failure, not the sweep's
        row.update(status="failed", error=describe(exc))
        return row, []
    row["encoding"] = "binary" if head.startswith(b"bplist") else ("xml" if head.lstrip().startswith(b"<") else "unknown")
    walk = Walk(ids, limits["max_nodes"], limits["max_depth"], limits["max_blob"], keep)
    try:
        if key:
            node, problem = dig(tree, key)
            if problem:
                row.update(status="failed", error=problem)
                return row, []
            row["key"] = key
            parts = key.split(".")
            if any(SECRET_KEY.search(p) for p in parts):
                row["value"] = walk.withhold(node, parts)
            else:
                row["value"] = walk.convert(node, parts, 0)
        else:
            row["value"] = walk.convert(tree, [], 0)
            if isinstance(tree, dict):
                row["keys"] = sorted(str(k) for k in tree)
    except Budget as exc:
        row.pop("value", None)
        row.update(status="skipped", reason="%s: not converted; select a smaller part with key, or raise the bound" % exc)
        return row, []
    except RecursionError as exc:
        row.pop("value", None)
        row.update(status="failed", error=describe(exc))
        return row, []
    row["status"] = "parsed"
    row["nodes"] = walk.nodes
    row["binary_values"] = walk.binary
    row["withheld_values"] = walk.withheld
    return row, walk.found


def bound(args, name, default):
    value = args.get(name, default)
    if not isinstance(value, int) or isinstance(value, bool) or value < 1:
        fail("%s must be a positive integer" % name, **{name: value})
    return value


def main():
    started = time.monotonic()
    try:
        args = json.load(sys.stdin)
    except ValueError as exc:
        fail("arguments are not valid JSON", reason=str(exc))
    path = args.get("path")
    if not isinstance(path, str) or not path:
        fail("path is required: a .plist file or a directory to walk")
    if not os.path.exists(path):
        fail("no such file or directory", path=path)
    max_blob = args.get("max_blob", DEFAULT_MAX_BLOB)
    if not isinstance(max_blob, int) or isinstance(max_blob, bool) or max_blob < 0:
        fail("max_blob must be a non-negative integer")
    limit = bound(args, "limit", 200)
    inline_bytes = bound(args, "max_inline_bytes", DEFAULT_INLINE_BYTES)
    limits = {
        "max_blob": max_blob,
        "max_file_bytes": bound(args, "max_file_bytes", DEFAULT_MAX_FILE_BYTES),
        "max_nodes": bound(args, "max_nodes", DEFAULT_MAX_NODES),
        "max_depth": bound(args, "max_depth", DEFAULT_MAX_DEPTH),
    }
    max_seconds = args.get("max_seconds", DEFAULT_MAX_SECONDS)
    if not isinstance(max_seconds, (int, float)) or isinstance(max_seconds, bool) or max_seconds < 0:
        fail("max_seconds must be a non-negative number", max_seconds=max_seconds)
    key = args.get("key")
    if key is not None and (not isinstance(key, str) or not key):
        fail("key must be a non-empty string")
    write_values = args.get("write_values", False)
    if not isinstance(write_values, bool):
        fail("write_values must be true or false")
    out_file = args.get("out_file")
    if out_file is not None and (not isinstance(out_file, str) or not out_file):
        fail("out_file must be a non-empty string")
    named = out_file
    if out_file is not None:
        resolve_output(out_file, "out_file")   # refuses a place outside the run, or under inputs/
    if not os.path.isdir(path) and not os.path.isfile(path):
        fail("path is neither a regular file nor a directory", path=path)

    # Refused before anything is read: a values file that cannot be made, an out_file
    # that already exists. Nothing is overwritten, and nothing is half written.
    try:
        values = SecretValues(write_values)
    except SecretValuesRefused as exc:
        fail(str(exc), write_values=True)
    sink = None
    if named:
        try:
            # The name as the caller gave it, not where a link would send it: O_EXCL refuses a name
            # that exists, a link (a dangling one included) as much as a file.
            Path(named).parent.mkdir(parents=True, exist_ok=True)
            fd = os.open(named, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o644)
        except FileExistsError:
            values.close()
            fail("out_file already exists; the tool does not overwrite: use a new name", out_file=named)
        except OSError as exc:
            values.close()
            fail("out_file could not be created", out_file=named, reason=describe(exc))
        sink = os.fdopen(fd, "w", encoding="utf-8", newline="\n")
    paging = None if sink else LosslessPage("plist_read", [path, key], limit, inline_bytes)

    counter = [0]

    def next_id():
        counter[0] += 1
        return "F%06d" % counter[0]

    inline = []
    inline_state = {"bytes": 0, "full": False, "bounded_by_bytes": False}
    totals = {"parsed": 0, "failed": 0, "skipped": 0, "not_attempted": 0, "binary_plist_files": 0,
              "files_with_withheld_values": 0, "binary_values": 0, "withheld_values": 0}
    first = {"failed": [], "skipped": [], "not_attempted": []}
    notes = {"links_not_followed": 0, "files_not_matched": 0, "not_regular_files": 0, "directories_unreadable": 0}
    problems = []
    rows_total = [0]

    def take(row, found):
        rows_total[0] += 1
        state = row["status"]
        totals[state] += 1
        if state != "parsed" and len(first[state]) < FIRST_FAILURES:
            first[state].append({"file": row["file"], "why": row.get("error") or row.get("reason")})
        if state == "parsed":
            totals["binary_values"] += row["binary_values"]
            totals["withheld_values"] += row["withheld_values"]
            if row["withheld_values"]:
                totals["files_with_withheld_values"] += 1
            if row.get("encoding") == "binary":
                totals["binary_plist_files"] += 1
        for fid, locator, value in found:
            values.add(fid, {"file": row["file"], **locator}, value)
        if sink:
            line = json.dumps(row, default=str, sort_keys=True)
            sink.write(line + "\n")
            sink.flush()
            if not inline_state["full"] and len(inline) < limit:
                if inline_state["bytes"] + len(line) <= inline_bytes:
                    inline.append(row)
                    inline_state["bytes"] += len(line)
                else:
                    inline_state["bounded_by_bytes"] = True
                    inline_state["full"] = True
            else:
                inline_state["full"] = True
        else:
            paging.add(row)

    def visit(file):
        if time.monotonic() - started > max_seconds:
            totals["not_attempted"] += 1
            if len(first["not_attempted"]) < FIRST_FAILURES:
                first["not_attempted"].append({"file": file, "why": "max_seconds (%s) passed before it was reached" % max_seconds})
            return
        row, found = read_one(file, key, limits, next_id, write_values)
        take(row, found)

    matched = 0
    if os.path.isdir(path):
        def on_error(exc):
            notes["directories_unreadable"] += 1
            if len(problems) < FIRST_FAILURES:
                problems.append({"path": getattr(exc, "filename", None), "why": describe(exc)})

        for dirpath, dirs, names in os.walk(path, onerror=on_error):
            dirs.sort()
            notes["links_not_followed"] += sum(1 for d in dirs if os.path.islink(os.path.join(dirpath, d)))
            for name in sorted(names):
                full = os.path.join(dirpath, name)
                if os.path.islink(full):
                    notes["links_not_followed"] += 1
                    continue
                if not name.lower().endswith((".plist", ".btm")):
                    notes["files_not_matched"] += 1
                    continue
                try:
                    regular = stat.S_ISREG(os.lstat(full).st_mode)
                except OSError:
                    regular = False
                if not regular:
                    notes["not_regular_files"] += 1
                    continue
                matched += 1
                visit(full)
    else:
        matched = 1
        visit(path)

    values.close()
    if sink:
        sink.flush()
        os.fsync(sink.fileno())
        sink.close()
        page = {"matched": rows_total[0], "returned": len(inline), "truncated": rows_total[0] > len(inline),
                "inline_byte_limit": inline_bytes}
        if inline_state["bounded_by_bytes"]:
            page["inline_bounded_by_bytes"] = True
        complete = named
    else:
        page = paging.finish()
        inline = paging.page
        complete = page.get("all_results")
    done = totals["parsed"]
    status = "complete" if done == matched else ("failed" if done == 0 and matched else "partial")
    result = {
        "path": path,
        "parser": PARSER,
        "status": status,
        "files": inline,
        "file_count": rows_total[0],
        "files_inline": len(inline),
        "found": matched,
        "complete_files": complete,
        "inline_limited": bool(page["truncated"]),
        "inline_bounded_by_bytes": bool(page.get("inline_bounded_by_bytes")),
        "inline_byte_limit": inline_bytes,
        **({"kept_earlier_larger_result": page["kept_earlier_larger_result"]} if page.get("kept_earlier_larger_result") else {}),
        "binary_files": totals["binary_plist_files"],
        "counts": {"matched": matched, "parsed": totals["parsed"], "failed": totals["failed"],
                   "skipped_over_a_bound": totals["skipped"], "not_attempted": totals["not_attempted"]},
        "first_problems": {k: v for k, v in first.items() if v},
        "walk": {**notes, "problems": problems},
        "limits": {**limits, "max_seconds": max_seconds},
        "secret_bearing": {
            "binary_values_not_printed": totals["binary_values"],
            "withheld_by_key_name": totals["withheld_values"],
            "files_with_withheld_values": totals["files_with_withheld_values"],
        },
        "secret_values": values.summary(),
        "note": "Dates are converted from the Apple epoch (2001-01-01 UTC) and returned as UTC. No binary value "
                "is printed, hashed or previewed, and a value under a key named for a secret is withheld: each is "
                "a locator (finding_id, key path, kind, length). `extracted_file_mtime` is the mtime of the file "
                "as read here, a working copy's, not the original's. A preference file says what a setting is "
                "on disk, not what it was, when it was changed or by whom. A parsed file is a structural "
                "reading: NSKeyedArchiver object graphs are not resolved.",
    }
    print(json.dumps(result, indent=2, default=str))
    if status == "failed":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
