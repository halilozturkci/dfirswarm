#!/usr/bin/env python3
"""Read a jump list, and hand the link structures inside it to lnk_parse.

A jump list outlives the Recent folder and outlives the file it points at, which
is why it answers "what did this user open, and from where" when nothing else
does. Two formats:

  *.automaticDestinations-ms  an OLE compound file. Each numbered stream is a
                              link structure; the DestList stream is the index,
                              holding the entry number, the host the file was
                              on, an access count and the last access time.
  *.customDestinations-ms     no container at all: link structures one after
                              another, found by their own 20-byte header.

The design here is deliberate. The DestList's fixed fields have moved between
Windows versions and a parser that guesses at them quietly returns wrong times,
so this reads the fields that are stable, validates each entry before trusting
it, and stops and says so when the layout stops making sense. The substance —
target path, volume serial, the three target timestamps — comes from the link
structures themselves, which are written out for `lnk_parse`, a parser that
already handles them properly.

The file name's leading hex is the application id. It identifies the
application, and published lists map the common ones; quote the id and the
source you resolved it with rather than asserting the application from memory.

Every link structure is read and, with out_dir, written out. The page of links
returned inline for each file is `limit` long, and when there are more the whole
list is written to a file the output names. A link file already in out_dir is
never overwritten with different bytes: two jump lists with the same name in
different folders both keep their links.
"""
import binascii
import datetime
import json
import os
import re
import struct
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

FILETIME_EPOCH = datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc)
LNK_MAGIC = bytes([0x4C, 0x00, 0x00, 0x00]) + binascii.unhexlify("0114020000000000c000000000000046")
DESTLIST_HEADER = 32


def fail(message, **extra):
    print(json.dumps({"error": message, **extra}))
    raise SystemExit(1)


def filetime(value):
    if not value:
        return None
    try:
        return (FILETIME_EPOCH + datetime.timedelta(microseconds=value // 10)).isoformat().replace("+00:00", "Z")
    except (OverflowError, OSError):
        return None


def parse_destlist(data):
    """Entry layout per Joachim Metz's jump list documentation; version aware."""
    out = {"entries": [], "problems": []}
    if len(data) < DESTLIST_HEADER:
        out["problems"].append("the DestList stream is shorter than its header")
        return out
    version, count, pinned = struct.unpack_from("<III", data, 0)
    out["destlist_version"] = version
    out["entries_claimed"] = count
    out["pinned_claimed"] = pinned
    if version not in (1, 3, 4):
        out["problems"].append("DestList version %d is not one this parser knows; entries are not read" % version)
        return out
    trailer = 0 if version == 1 else 4
    offset = DESTLIST_HEADER
    while offset + 118 <= len(data):
        chars = struct.unpack_from("<H", data, 0x74 + offset)[0]
        end = offset + 118 + chars * 2 + trailer
        if chars > 2048 or end > len(data):
            out["problems"].append(
                "entry %d claims a %d-character path, which does not fit; stopped here"
                % (len(out["entries"]) + 1, chars))
            break
        host = data[offset + 0x48:offset + 0x58].split(b"\x00", 1)[0].decode("ascii", "replace")
        number, = struct.unpack_from("<I", data, offset + 0x58)
        access_count, = struct.unpack_from("<I", data, offset + 0x64)
        modified, = struct.unpack_from("<Q", data, offset + 0x68)
        pin, = struct.unpack_from("<i", data, offset + 0x70)
        path = data[offset + 118:offset + 118 + chars * 2].decode("utf-16-le", "replace")
        out["entries"].append({
            "entry_number": number,
            "stream": "%x" % number,
            "path": path,
            "hostname": host,
            "access_count": access_count,
            "last_access": filetime(modified),
            "pinned": pin != -1,
        })
        offset = end
    if count and len(out["entries"]) != count:
        out["problems"].append(
            "the header claims %d entries and %d were read" % (count, len(out["entries"])))
    return out


def split_lnks(data):
    """Find every link structure by its own header, wherever it sits."""
    found, at = [], 0
    while True:
        hit = data.find(LNK_MAGIC, at)
        if hit < 0:
            break
        found.append(hit)
        at = hit + 4
    out = []
    for i, start in enumerate(found):
        end = found[i + 1] if i + 1 < len(found) else len(data)
        out.append((start, data[start:end]))
    return out


def resolve_output(out):
    """Where `out` really lands, refusing anything outside the run directory.

    A string check is not enough: `work/../inputs/x` and an absolute path
    both name a file the tool must not write, and neither starts with
    "inputs/". Resolving first and comparing directories is what actually
    holds, and the read-only inputs are the one place extracted bytes must
    never appear -- a later integrity check would report the evidence as
    modified.
    """
    root = Path.cwd().resolve()
    dest = (root / out).resolve() if not Path(out).is_absolute() else Path(out).resolve()
    if dest == root or root not in dest.parents:
        fail("out_dir must be a directory inside the run directory", out_dir=str(out))
    inputs = root / "inputs"
    if dest == inputs or inputs in dest.parents:
        fail("out_dir cannot be under inputs/", out_dir=str(out))
    return dest


def write_stream(out_dir, name, payload):
    """Write one link structure, and never over another one.

    The name is the source file's name and the stream's, whole. When that file
    already holds different bytes (a jump list of the same name from another
    folder, or two names that differ only in characters a file name cannot
    carry) the next free numbered name is used instead.
    """
    os.makedirs(out_dir, exist_ok=True)
    safe = re.sub(r"[^A-Za-z0-9._-]", "_", name) or "stream"
    if len(safe) > 200:
        # A file system refuses a name much longer than this. The digest keeps
        # the shortened name unique; the whole name stays in the output.
        safe = safe[:160] + "-" + hashlib.sha256(name.encode("utf-8")).hexdigest()[:16]
    target = os.path.join(out_dir, safe + ".lnk")
    n = 2
    while os.path.exists(target):
        with open(target, "rb") as fh:
            if fh.read() == payload:
                return target
        target = os.path.join(out_dir, "%s-%d.lnk" % (safe, n))
        n += 1
    with open(target, "wb") as fh:
        fh.write(payload)
    return target


def page_links(result, links):
    page = links.finish()
    result["links"] = links.page
    result["link_count"] = page["matched"]
    result.update(page)
    if page["truncated"]:
        result["links_truncated"] = True


def read_automatic(path, out_dir, limit):
    try:
        import olefile
    except ImportError as exc:
        return {"file": path, "error": "olefile is not installed: python3 -m pip install olefile",
                "reason": str(exc)}
    if not olefile.isOleFile(path):
        return {"file": path, "error": "not an OLE compound file; is it a customDestinations-ms?"}
    ole = olefile.OleFileIO(path)
    result = {"file": path, "format": "automaticDestinations-ms", "streams": [], "links": []}
    try:
        names = ["/".join(p) for p in ole.listdir()]
        result["stream_names"] = names
        if "DestList" in names:
            result.update(parse_destlist(ole.openstream("DestList").read()))
        else:
            result["problems"] = ["there is no DestList stream in this file"]
        by_stream = {e["stream"]: e for e in result.get("entries", [])}
        links = LosslessPage("jumplist", [path, "links", out_dir], limit)
        for name in names:
            if name == "DestList":
                continue
            payload = ole.openstream(name).read()
            entry = {"stream": name, "bytes": len(payload), "is_link": payload[:4] == LNK_MAGIC[:4]}
            known = by_stream.get(name.lower())
            if known:
                entry["path"] = known["path"]
                entry["last_access"] = known["last_access"]
            if out_dir and entry["is_link"]:
                entry["written_to"] = write_stream(out_dir, os.path.basename(path) + "-" + name, payload)
            links.add(entry)
        page_links(result, links)
    finally:
        ole.close()
    return result


def read_custom(path, out_dir, limit):
    with open(path, "rb") as fh:
        data = fh.read()
    result = {"file": path, "format": "customDestinations-ms", "links": []}
    links = LosslessPage("jumplist", [path, "links", out_dir], limit)
    for i, (offset, payload) in enumerate(split_lnks(data)):
        entry = {"offset": offset, "bytes": len(payload), "is_link": True}
        if out_dir:
            entry["written_to"] = write_stream(out_dir, "%s-%04d" % (os.path.basename(path), i), payload)
        links.add(entry)
    page_links(result, links)
    if not result["links"]:
        result["problems"] = ["no link structure header found in this file"]
    return result


def main():
    try:
        args = json.load(sys.stdin)
    except ValueError as exc:
        fail("arguments are not valid JSON", reason=str(exc))

    path = args.get("path")
    if not isinstance(path, str) or not path:
        fail("path is required: a jump list file or a directory of them")

    limit = args.get("limit", 500)
    if not isinstance(limit, int) or isinstance(limit, bool) or limit < 1:
        fail("limit must be a positive integer", limit=args.get("limit"))

    out_dir = args.get("out_dir")
    if out_dir is not None and (not isinstance(out_dir, str) or not out_dir):
        fail("out_dir must be a directory path under work/")
    if out_dir is not None:
        out_dir = str(resolve_output(out_dir).relative_to(Path.cwd().resolve()))

    targets = []
    if os.path.isdir(path):
        for root, dirs, names in os.walk(path):
            dirs.sort()                                   # the same order on every run
            for name in sorted(names):
                if name.lower().endswith(("destinations-ms",)):
                    targets.append(os.path.join(root, name))
    elif os.path.isfile(path):
        targets = [path]
    else:
        fail("no such file or directory", path=path)
    if not targets:
        fail("no jump list files under that directory", path=path)

    files = []
    for target in targets:
        try:
            if target.lower().endswith("customdestinations-ms"):
                files.append(read_custom(target, out_dir, limit))
            else:
                files.append(read_automatic(target, out_dir, limit))
        except Exception as exc:                              # one bad file must not end the sweep
            files.append({"file": target, "error": "%s: %s" % (type(exc).__name__, exc)})
        app_id = os.path.basename(target).split(".")[0]
        if re.fullmatch(r"[0-9a-f]{16}", app_id):
            files[-1]["application_id"] = app_id

    print(json.dumps({
        "files": files,
        "file_count": len(files),
        "note": "The DestList gives the index and the access counts; the target path, the volume "
                "serial and the three target timestamps come from the link structures, so run "
                "lnk_parse over what was written to out_dir before citing any of them.",
    }, indent=2))


if __name__ == "__main__":
    main()
