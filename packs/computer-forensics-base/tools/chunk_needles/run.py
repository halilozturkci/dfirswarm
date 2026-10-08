#!/usr/bin/env python3
"""Scan a file, or one inode of an image streamed through icat, for ASCII and UTF-16LE needles.

The answer is where each needle is: per needle the number of occurrences as ASCII and as
UTF-16LE, and for each occurrence a locator (an id, the offset in the scanned stream, the
encoding, how many bytes of context surround it). The context bytes are NOT returned by
default: they are where a password, a token or a card number sits. `write_values: true`, in a
job run with `secret_output: true`, writes them to a 0600 file under $OUT, and the answer names
the file. Never put a secret in `needles`: the arguments of a call are recorded in the trace.

What it finds, exactly: every occurrence of each needle, overlapping ones included, whatever
`chunk` is; a match is held back until its context is in the read, so a read boundary neither
loses a match nor cuts its context. `source` names the stream: the file, or the image, the
volume offset, the inode, and any sector size given. The stream is read once and never held whole.
"""
import json, re, shutil, sys, subprocess, os

TOOL = {"name": "chunk_needles", "version": 6}
CHUNK_DEFAULT = 8 * 1024 * 1024
CHUNK_MIN, CHUNK_MAX = 16, 256 * 1024 * 1024
CONTEXT_MAX = 65536
HITS_MAX = 1_000_000
NEEDLES_MAX = 1000
NEEDLE_BYTES_MAX = 4096
ROW_CAP = 20_000_000
SLICE = 256 * 1024                 # positions searched, sorted and emitted together: hits come out in offset order, whatever chunk is
SECTOR_MAX = 65536
INODE = re.compile(r"^\d+(-\d+(-\d+)?)?$")

def _catalogue_slug(path):
    """The directory name the kickoff's catalogue gives an input: its path under
    inputs/ with every byte outside [A-Za-z0-9._-] made "_" (evidence-catalog.sh)."""
    import os, re
    rel = os.fsencode(os.path.relpath(path, "inputs"))
    return os.fsdecode(re.sub(rb"[^A-Za-z0-9._-]", b"_", rel))


def _inputs_roots():
    """inputs/, and each set held in place as a link directly under it (inputs.json names the sets): the only links followed.
    Any other link under inputs/ is a name and not a place to walk: following one could leave the evidence for the rest of the file system."""
    import json, os
    roots = ["inputs"]
    try:
        with open("inputs.json", encoding="utf-8") as fh:
            sets = json.load(fh).get("sets") or []
    except (OSError, ValueError, AttributeError):
        sets = []
    for entry in sets:
        name = entry.get("name") if isinstance(entry, dict) else None
        if isinstance(name, str) and name and "/" not in name and os.path.islink(os.path.join("inputs", name)):
            roots.append(os.path.join("inputs", name))
    return roots


def _resolve_image(explicit=None):
    """A pack tool belongs to no case: find the image under inputs/ instead of
    baking one in. One candidate is used; several mean the caller must say which.
    An image is known by its extension or, lacking one (a raw `dd` of a web
    server named after the host), by the catalogue: the kickoff writes
    catalog/<input>/partitions.txt for every input it read as a disk."""
    import glob, os
    if explicit:
        return explicit
    cands = []
    for ext in ("*.E01", "*.e01", "*.raw", "*.dd", "*.001", "*.img", "*.vhd", "*.vhdx"):
        cands += glob.glob(os.path.join("inputs", ext))
    seen = set()
    for root_dir in _inputs_roots():
        for base, _dirs, files in os.walk(root_dir, followlinks=False):
            for f in files:
                p = os.path.join(base, f)
                if os.path.isfile(os.path.join("catalog", _catalogue_slug(p), "partitions.txt")):
                    cands.append(p)
    cands = sorted(set(cands))
    if len(cands) == 1:
        return cands[0]
    if not cands:
        raise SystemExit('{"ok": false, "error": "no disk image under inputs/; pass image="}')
    raise SystemExit('{"ok": false, "error": "several images under inputs/; pass image=", "candidates": %s}' % json.dumps(cands))


def _resolve_offset(image, explicit=None):
    """The volume's start sector for icat -o. Given, it is used as is; not
    given, the catalogue says: one filesystem catalogued (catalog/<input>/p<start>/)
    is that start, several mean the caller must say which, none is sector 0."""
    import os, re
    if explicit is not None:
        return explicit
    root = os.path.join("catalog", _catalogue_slug(image))
    starts = sorted(int(d[1:]) for d in (os.listdir(root) if os.path.isdir(root) else [])
                    if re.fullmatch(r"p\d+", d) and os.path.isdir(os.path.join(root, d)))
    if len(starts) == 1:
        return starts[0]
    if not starts:
        return 0
    raise SystemExit('{"ok": false, "error": "several filesystems in %s; pass offset= (a start sector, see %s/partitions.txt)", "candidates": %s}' % (image, root, json.dumps(starts)))


def _resolve_catalog(explicit=None):
    """The catalogue directory for the one image the kickoff catalogued, or
    the one named: by its name under catalog/, as the index lists it
    (catalog=Case4.E01 was a traceback), or by its path."""
    import os
    root = "catalog"
    subs = sorted(d for d in os.listdir(root) if os.path.isdir(os.path.join(root, d))) if os.path.isdir(root) else []
    if explicit:
        for cand in (explicit, os.path.join(root, explicit)):
            if os.path.isdir(cand):
                return cand
        raise SystemExit(json.dumps({"ok": False, "error": "no catalogue %s" % explicit, "candidates": subs}))
    if not os.path.isdir(root):
        raise SystemExit('{"ok": false, "error": "no catalog/ in this run; pass catalog="}')
    if len(subs) == 1:
        return os.path.join(root, subs[0])
    if not subs:
        raise SystemExit('{"ok": false, "error": "catalog/ is empty; pass catalog="}')
    # A disk and a memory image catalogue two directories, and only the
    # disk's has filesystems (partitions.txt): with one such, it is the one.
    disks = [d for d in subs if os.path.isfile(os.path.join(root, d, "partitions.txt"))]
    if len(disks) == 1:
        return os.path.join(root, disks[0])
    raise SystemExit('{"ok": false, "error": "several catalogues; pass catalog=", "candidates": %s}' % json.dumps(subs))

import errno
import hashlib
import tempfile
from pathlib import Path


def describe(exc):
    code = errno.errorcode.get(exc.errno, "") if getattr(exc, "errno", None) else ""
    return "%s%s: %s" % (type(exc).__name__, " " + code if code else "", getattr(exc, "strerror", None) or str(exc))


class SecretValuesRefused(Exception):
    pass


class SecretValues:
    """Where a value goes when, and only when, the caller asked for it.

    The reference implementation of the secret-safe output pattern: copy this
    class unchanged into a tool that has to produce a secret, and call `add`
    once per finding with the finding's id, its locator and the value. With
    `enabled` false it writes nothing and `summary()` says so.
    """

    NAME = "chunk-needles-values.jsonl"

    def __init__(self, enabled: bool):
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
                "file, not a sealed secret output. Run this as job_run tool=chunk_needles with "
                "secret_output: true, and ask again there. Nothing was written."
            )
        self.path = Path(self.out) / self.NAME
        self.shown = "store/jobs/%s/out/%s" % (re.sub(r"[^A-Za-z0-9_.-]", "_", self.job), self.NAME)
        # Created now, before anything is scanned: a file or a link already at that name is
        # refused by name at once (O_EXCL does not follow a link, a dangling one included),
        # instead of failing, or writing through it, after the scan. With nothing found it
        # stays as an empty file, mode 0600, and the answer says written: 0.
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            fd = os.open(str(self.path), os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        except FileExistsError:
            raise SecretValuesRefused("the values file already exists: %s" % self.path)
        except OSError as exc:
            raise SecretValuesRefused("the values file could not be created: %s (%s)" % (self.path, describe(exc)))
        self._fh = os.fdopen(fd, "w", encoding="utf-8")

    def add(self, finding_id: str, locator: dict, value: str) -> None:
        if not self.enabled:
            return
        self._fh.write(json.dumps({"finding_id": finding_id, **locator, "value": value}, ensure_ascii=False))
        self._fh.write("\n")
        self.written += 1

    def close(self) -> None:
        if self._fh is not None:
            self._fh.flush()
            os.fsync(self._fh.fileno())
            self._fh.close()
            self._fh = None

    def summary(self) -> dict:
        return {
            "requested": self.enabled,
            "written": self.written,
            "values_file": self.shown if self.enabled else None,
            "contains_secret_values": self.written > 0,
            "format": "JSON Lines, mode 0600: finding_id, source, offset, needle, encoding, value (the printable context around the match)" if self.enabled else None,
        }


def earlier_answers(path):
    """How many other files answer this same question in the folder (name.ext, name.2.ext, ...): one more for every different
    answer, and none is deleted, so the count is said."""
    stem, ext = os.path.splitext(os.path.basename(str(path)))
    base = re.sub(r"\.\d+$", "", stem)
    rx = re.compile(r"^%s(\.\d+)?%s$" % (re.escape(base), re.escape(ext)))
    try:
        return max(0, sum(1 for n in os.listdir(os.path.dirname(str(path)) or ".") if rx.match(n)) - 1)
    except OSError:
        return 0


def same_bytes(a, b):
    """Two files with the same bytes (compared in blocks, never whole)."""
    try:
        if os.path.getsize(a) != os.path.getsize(b):
            return False
        with open(a, "rb") as fa, open(b, "rb") as fb:
            while True:
                x, y = fa.read(1 << 20), fb.read(1 << 20)
                if x != y:
                    return False
                if not x:
                    return True
    except OSError:
        return False


def publish(tmp, path, shown):
    """Move a finished file to `path` without replacing what is there: a file at the name is an earlier answer (a complete
    one, perhaps, where this run was cut short) and stays; this one is kept beside it as name.2.ext, unless it is the
    same bytes, when the file already there is it. Returns the path it has
    and the name to show for it."""
    stem, ext = os.path.splitext(str(path))
    shown_stem, _ = os.path.splitext(shown)
    k = 1
    while True:
        suffix = "" if k == 1 else ".%d" % k
        candidate = Path(stem + suffix + ext)
        try:
            os.link(tmp, candidate)
        except FileExistsError:
            if same_bytes(tmp, candidate):                # the same answer again (a page of the same search): the file is already there
                os.unlink(tmp)
                return candidate, shown_stem + suffix + ext
            k += 1
            continue
        except OSError:                                   # a file system with no hard links: a look, then a rename
            if os.path.lexists(candidate):
                if same_bytes(tmp, candidate):
                    os.unlink(tmp)
                    return candidate, shown_stem + suffix + ext
                k += 1
                continue
            os.rename(tmp, candidate)
            return candidate, shown_stem + suffix + ext
        os.unlink(tmp)
        return candidate, shown_stem + suffix + ext


class Locators:
    """One needle's locators: an inline page, and the whole list in a file once it is more than the page."""

    def __init__(self, tool, key, limit):
        self.limit, self.page, self.total, self.stopped_at = limit, [], 0, None
        self.tool = re.sub(r"[^A-Za-z0-9_.-]", "_", tool)
        digest = hashlib.sha256(json.dumps(key, sort_keys=True, default=str).encode("utf-8")).hexdigest()[:16]
        name = "%s-%s.jsonl" % (self.tool, digest)
        job, out = os.environ.get("JOB_ID"), os.environ.get("OUT")
        if job and out:
            self.path = Path(out) / "tool-output" / name
            self.shown = "store/jobs/%s/out/tool-output/%s" % (re.sub(r"[^A-Za-z0-9_.-]", "_", job), name)
        else:
            agent = re.sub(r"[^A-Za-z0-9_.-]", "_", os.environ.get("AGENT_ID") or "tool")
            self.path = Path("work") / agent / "tool-output" / name
            self.shown = str(self.path)
        self.fh = self.tmp = self.error = None
        self.written = 0

    def _open(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd, name = tempfile.mkstemp(dir=self.path.parent, prefix=".%s-" % self.tool)
        self.tmp, self.fh = Path(name), os.fdopen(fd, "w", encoding="utf-8")
        for row in self.page:
            self.fh.write(json.dumps(row, ensure_ascii=False) + "\n")
            self.written += 1

    def add(self, row):
        self.total += 1
        if len(self.page) < self.limit:
            self.page.append(row)
            return
        if self.fh is None and self.error is None:
            try:
                self._open()
            except OSError as exc:
                self.error = "the whole result could not be written (%s: %s)" % (self.path.parent, exc.strerror or exc)
        if self.fh:
            if self.written < ROW_CAP:
                self.fh.write(json.dumps(row, ensure_ascii=False) + "\n")
                self.written += 1
            elif self.stopped_at is None:
                self.stopped_at = row["off"]

    def discard(self):
        """Close and remove the file being written, if it is still there: a run that did not finish keeps no half file."""
        try:
            if self.fh and not self.fh.closed:
                self.fh.close()
        except OSError:
            pass
        if self.tmp is not None:
            try:
                os.unlink(self.tmp)
            except OSError:
                pass

    def finish(self):
        info = {"matched": self.total, "returned": len(self.page), "truncated": self.total > len(self.page)}
        if self.fh:
            self.fh.flush()
            os.fsync(self.fh.fileno())
            self.fh.close()
            self.path, self.shown = publish(self.tmp, self.path, self.shown)
            self.tmp = None
            info["all_results"] = self.shown
            info["earlier_answers"] = earlier_answers(self.path)
            info["all_results_format"] = "JSON Lines, one locator per occurrence: finding_id, off, enc, context_length"
            if self.stopped_at is not None:
                info["all_results_stopped_at_offset"] = self.stopped_at
                info["all_results_cap_rows"] = ROW_CAP
        if self.error:
            info["all_results_error"] = self.error
        return info


def fail(message, **extra):
    print(json.dumps({"error": message, "tool": TOOL, **extra}))
    sys.exit(1)


def whole(args, key, default, low, high):
    value = args.get(key)
    if value is None:
        return default
    if not isinstance(value, int) or isinstance(value, bool) or not low <= value <= high:
        fail("%s is a whole number from %d to %d" % (key, low, high), **{key: value})
    return value


try:
    args = json.load(sys.stdin)
except ValueError as exc:
    fail("arguments are not valid JSON", reason=str(exc))
if not isinstance(args, dict):
    fail("arguments are a JSON object")
needles = args.get("needles") or ""
if isinstance(needles, list) and all(isinstance(n, str) for n in needles):
    need_list = [n for n in needles if n]
elif isinstance(needles, str):
    need_list = [n for n in needles.split("|") if n]
else:
    fail("needles is a pipe-separated string or a list of strings")
path = args.get("path") or ""
inode = args.get("inode")
context = whole(args, "context", 60, 0, CONTEXT_MAX)          # 0 is 0, not the default
max_hits = whole(args, "max_hits", 20, 1, HITS_MAX)
chunk = whole(args, "chunk", CHUNK_DEFAULT, CHUNK_MIN, CHUNK_MAX)
sector_size = args.get("sector_size")
if sector_size is not None and (not isinstance(sector_size, int) or isinstance(sector_size, bool)
                                or sector_size < 512 or sector_size > SECTOR_MAX or sector_size % 512):
    fail("sector_size must be a multiple of 512 from 512 to %d (the Sleuth Kit's -b takes no other)" % SECTOR_MAX, sector_size=sector_size)
write_values = args.get("write_values", False)
if not isinstance(write_values, bool):
    fail("write_values is true or false")
need_list = list(dict.fromkeys(need_list))          # a needle given twice is one needle
if not need_list:
    fail("needles required, pipe-separated")
if len(need_list) > NEEDLES_MAX:
    fail("at most %d needles" % NEEDLES_MAX, given=len(need_list))
variants = []
for n in need_list:
    try:
        raw, wide = n.encode("utf-8"), n.encode("utf-16le")
    except UnicodeEncodeError:
        fail("a needle is not text that can be encoded")
    if len(raw) > NEEDLE_BYTES_MAX:
        fail("a needle is longer than %d bytes" % NEEDLE_BYTES_MAX)
    variants.append((n, "ascii", raw))
    variants.append((n, "utf16le", wide))
longest = max(len(v[2]) for v in variants)
try:
    secret = SecretValues(write_values)
except SecretValuesRefused as exc:
    fail(str(exc), write_values="refused")


def scan_fh(fh, source):
    counts = {n: {"ascii": 0, "utf16le": 0} for n in need_list}
    key = [source["label"], source.get("image"), source.get("volume_offset_sectors"), source.get("inode"), source.get("sector_size"), context]
    pages = {n: Locators("chunk_needles", key + [n], max_hits) for n in need_list}
    next_id = [0]

    def emit(at, name, enc, nb, buf, base):
        i = at - base
        a, b = max(0, i - context), min(len(buf), i + len(nb) + context)
        raw = buf[a:b]
        next_id[0] += 1
        fid = "F%06d" % next_id[0]
        counts[name][enc] += 1
        pages[name].add({"finding_id": fid, "off": at, "enc": enc, "context_length": len(raw)})
        if write_values:
            secret.add(fid, {"source": source["label"], "offset": at, "needle": name, "encoding": enc},
                       "".join(chr(c) if 32 <= c < 127 else "." for c in raw))

    # buf holds the stream's bytes [base, base + len(buf)); positions below `done` are searched. A
    # position is searched once its context is in buf (or the stream has ended), so no match is cut.
    try:
        buf, base, done, scanned = b"", 0, 0, 0
        while True:
            data = fh.read(chunk)
            at_end = not data
            buf += data
            scanned += len(data)
            have = base + len(buf)
            process_end = have if at_end else have - (longest + context)
            if process_end > done:
                lo, hi = done - base, process_end - base
                a = lo
                while a < hi:
                    b = min(hi, a + SLICE)
                    found = []
                    for vi, (name, enc, nb) in enumerate(variants):
                        stop = min(len(buf), b + len(nb) - 1)
                        j = buf.find(nb, a, stop)
                        while j >= 0:
                            found.append((j, vi))
                            j = buf.find(nb, j + 1, stop)
                    found.sort()                          # by offset, then by needle order: the same list for any chunk
                    for j, vi in found:
                        name, enc, nb = variants[vi]
                        emit(base + j, name, enc, nb, buf, base)
                    a = b
                done = process_end
            if at_end:
                break
            keep_from = max(0, (done - context) - base)
            buf, base = buf[keep_from:], base + keep_from
        hits = {}
        for n in need_list:
            page = pages[n].finish()
            hits[n] = {**counts[n], "locations": pages[n].page, **page}
    finally:
        for n in need_list:
            pages[n].discard()                  # no half-written file is left when the run did not finish
    return hits, scanned


if path:
    if not os.path.isfile(path):
        print(json.dumps({"error": f"path not found: {path}"}))
        sys.exit(1)
    source = {"kind": "file", "path": path, "bytes": os.path.getsize(path)}
    source["label"] = path
    with open(path, "rb") as f:
        hits, scanned = scan_fh(f, source)
else:
    if inode is None:
        print(json.dumps({"error": "path or inode required"}))
        sys.exit(1)
    if isinstance(inode, bool) or not (isinstance(inode, int) and inode >= 0 or isinstance(inode, str) and INODE.match(inode)):
        fail("inode is a Sleuth Kit address: a number, or number-type-id for an NTFS stream (168-128-4)", inode=inode)
    image = _resolve_image(args.get("image"))
    if not os.path.isfile(image):
        print(json.dumps({"error": f"image not found: {image}"}))
        sys.exit(1)
    given_offset = args.get("offset")
    if given_offset is not None and (isinstance(given_offset, bool) or not isinstance(given_offset, int) or given_offset < 0):
        fail("offset is a volume offset in sectors, a whole number", offset=given_offset)
    if not shutil.which("icat"):
        fail("icat is not on PATH", install="brew install sleuthkit, or apt-get install -y sleuthkit")
    offset = _resolve_offset(image, given_offset)
    inode = "-".join(str(int(p)) for p in str(inode).split("-"))      # 084284 is address 84284
    cmd = ["icat"] + (["-b", str(sector_size)] if sector_size else []) + ["-o", str(offset), image, str(inode)]
    source = {"kind": "icat", "image": image, "volume_offset_sectors": offset, "inode": str(inode),
              "sector_size": sector_size, "command": " ".join(cmd)}
    source["label"] = f"icat:{inode}@{offset}"
    # Streamed, never held whole: capture_output kept a pagefile's gigabytes
    # in memory until the VM's kernel killed the tool, with no word said
    # (sixth CTF round, twice). stderr goes to a file so a chatty icat
    # cannot stall the pipe being read.
    with tempfile.TemporaryFile() as errf:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=errf)
        hits, scanned = scan_fh(proc.stdout, source)
        rc = proc.wait()
        errf.seek(0)
        err_text = errf.read().decode("utf-8", "replace").strip()
    if rc != 0:
        secret.close()
        print(json.dumps({"error": err_text or f"icat exit {rc}", "image": image, "inode": inode, "offset": offset, "scanned_bytes": scanned,
                          "note": "what was found before icat failed is not a result; any locator or values file written meanwhile is partial",
                          "secret_values": secret.summary()}))
        sys.exit(1)
secret.close()
print(json.dumps({
    "tool": TOOL, "source": source, "scanned_bytes": scanned, "hits": hits,
    "match_policy": "every occurrence by its start offset in the scanned stream, overlapping ones included, case-sensitive; each needle as UTF-8 and as UTF-16LE",
    "context": {"bytes_each_side": context, "returned_inline": False,
                "note": "context bytes are not returned: they are where a secret sits. write_values: true, in a job run with secret_output: true, writes them to a file under $OUT."},
    "secret_values": secret.summary(),
}))
