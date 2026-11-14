#!/usr/bin/env python3
"""A VirtualBox disk (VDI) that lies inside another image, read in place.

Two levels, and nothing written out on the way: the outer image (an E01 read
with pyewf, or a raw image) holds a volume at `offset`; in that volume the
VDI file is found by its data runs (the runs of an NTFS file, deleted or not:
lcn and clusters, a sparse run with lcn null), or, with no runs, lies
contiguous at vdi_offset; then the VDI's own block map gives the guest disk.

action=info reads the VDI header and its block map's counts and, with
pytsk3, the guest's partitions and file systems; ls lists a directory of a
guest file system (recursive, paged, nothing cut); extract writes one guest
file to output; read gives guest bytes at an offset (to output, or as hex
for 4096 bytes or fewer). Args come from JSON stdin.
"""
import bisect
import struct
import sys
import uuid
from datetime import datetime, timezone
# Lossless paging (the same in every library tool that pages): the page an
# agent reads stays small, and when there are more rows the whole result is
# written as JSON Lines under work/<agent>/tool-output and named.
import hashlib
import json
import os
import re
import tempfile
from pathlib import Path
import time

# The Sleuth Kit turns a FAT time (a wall-clock time stored with no zone) into seconds with the C library's mktime, in this
# process's time zone, and iso() writes those seconds as UTC: the times an answer gives are the same on every host only when
# that zone is UTC, so it is set before pytsk3 is loaded (a host in UTC+3 gave every FAT time three hours early).
os.environ["TZ"] = "UTC"
if hasattr(time, "tzset"):
    time.tzset()


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


VDI_SIGNATURE = 0xBEDA107F
BLOCK_FREE = 0xFFFFFFFF
BLOCK_ZERO = 0xFFFFFFFE
IMAGE_TYPES = {1: "dynamic", 2: "fixed", 3: "undo", 4: "differencing"}
INLINE_READ_MAX = 4096
CHUNK = 1 << 20


def fail(msg, **extra):
    print(json.dumps({"ok": False, "error": msg, **extra}))
    sys.exit(1)


def resolve_output(out):
    """Where `out` lands, refusing anything outside the run directory, the
    read-only inputs, and ledger/ and tools/, which the harness owns."""
    root = Path.cwd().resolve()
    dest = Path(out).resolve() if Path(out).is_absolute() else (root / out).resolve()
    if dest == root or root not in dest.parents:
        fail("output must stay inside the run directory", output=str(out))
    for owned in ("inputs", "ledger", "tools"):
        place = root / owned
        if dest == place or place in dest.parents:
            fail("output cannot be under %s/" % owned, output=str(out))
    return dest


def whole(name, default=None, low=0):
    v = args.get(name)
    if v is None or v == "":
        return default
    if isinstance(v, bool) or not isinstance(v, int) or v < low:
        fail("%s must be a whole number of at least %d" % (name, low), got=v)
    return v


def missing(name, why):
    """pytsk3 and pyewf: the disk and mobile images have them, not every
    image (the manifest declares them in optional_python), and a missing one
    is said rather than raised."""
    fail("%s is not installed" % name, why=why, hint="the disk and mobile images have pytsk3 and pyewf")


def load_pyewf():
    try:
        import pyewf
    except ImportError:
        missing("pyewf", "the image is an EWF (E01) file; pass a raw image instead to do without it")
    return pyewf


def load_pytsk3():
    try:
        import pytsk3
    except ImportError:
        missing("pytsk3", "ls, extract and the partition list read the guest's file systems with it; info's header and read work without it")
    return pytsk3


def have_pytsk3():
    try:
        import pytsk3  # noqa: F401
    except ImportError:
        return False
    return True


class RawImage:
    def __init__(self, path):
        self.fd = os.open(path, os.O_RDONLY)
        self.size = os.fstat(self.fd).st_size
        self.kind = "raw"

    def read(self, off, n):
        return os.pread(self.fd, n, off)


class EwfImage:
    """An E01 (and its other segments) through libewf, as one byte stream."""

    def __init__(self, path):
        pyewf = load_pyewf()
        self.handle = pyewf.handle()
        self.handle.open(pyewf.glob(path))
        self.size = self.handle.get_media_size()
        self.kind = "ewf"

    def read(self, off, n):
        self.handle.seek(off)
        return self.handle.read(n)


class Slice:
    """The outer volume: the image from `start` on."""

    def __init__(self, base, start):
        self.base, self.start = base, start
        self.size = max(0, base.size - start)

    def read(self, off, n):
        got = self.base.read(self.start + off, n)
        if len(got) != n:
            raise IOError("read at volume byte %d+%d is past the end of the image" % (off, n))
        return got


class RunFile:
    """A file laid out by its data runs in the volume; a sparse run reads as
    zeros, and a run that reaches past the image is an error, not zeros."""

    def __init__(self, volume, runs, cluster_size):
        self.volume, self.runs, self.cs = volume, runs, cluster_size
        self.starts, pos = [], 0
        for lcn, clusters in runs:
            self.starts.append(pos)
            pos += clusters * cluster_size
        self.size = pos
        self.sparse_bytes_read = 0

    def read(self, off, n):
        if off < 0 or off + n > self.size:
            raise IOError("read at %d+%d is past the %d bytes the data runs give" % (off, n, self.size))
        out = bytearray()
        while n:
            j = bisect.bisect_right(self.starts, off) - 1
            lcn, clusters = self.runs[j]
            rel = off - self.starts[j]
            take = min(n, clusters * self.cs - rel)
            if lcn is None:
                out += bytes(take)
                self.sparse_bytes_read += take
            else:
                try:
                    out += self.volume.read(lcn * self.cs + rel, take)
                except IOError:
                    raise IOError("run %d (lcn %d, %d clusters) reaches past the end of the image" % (j, lcn, clusters))
            off += take
            n -= take
        return bytes(out)


class VdiDisk:
    """The guest disk: the VDI's block map over the file that holds it."""

    def __init__(self, host, at):
        self.host, self.at = host, at
        if at + 0x200 > host.size:
            fail("vdi_offset %d leaves no room for a VDI header in the %d bytes there" % (at, host.size))
        h = host.read(at, 0x200)
        sig, version = struct.unpack_from("<II", h, 0x40)
        if sig != VDI_SIGNATURE:
            fail("no VDI header at vdi_offset %d: the signature at +0x40 is %08x, not beda107f" % (at, sig), first_bytes=h[:0x48].hex())
        major, minor = version >> 16, version & 0xFFFF
        if major != 1:
            fail("VDI header version %d.%d: this reads version 1 headers only" % (major, minor))
        (self.header_size, itype, self.flags) = struct.unpack_from("<III", h, 0x48)
        self.image_type = IMAGE_TYPES.get(itype, "unknown (%d)" % itype)
        self.text = h[:0x40].split(b"\0", 1)[0].decode("latin-1").strip()
        self.description = h[0x54:0x154].split(b"\0", 1)[0].decode("utf-8", "replace")
        self.off_blocks, self.off_data = struct.unpack_from("<II", h, 0x154)
        cyl, heads, sectors, sector_size = struct.unpack_from("<IIII", h, 0x15C)
        self.geometry = {"cylinders": cyl, "heads": heads, "sectors": sectors, "sector_size": sector_size}
        (self.size,) = struct.unpack_from("<Q", h, 0x170)
        self.block_size, self.extra, self.blocks, self.allocated_header = struct.unpack_from("<IIII", h, 0x178)
        self.uuid = str(uuid.UUID(bytes_le=h[0x188:0x198]))
        self.parent_uuid = str(uuid.UUID(bytes_le=h[0x1A8:0x1B8]))
        self.version = "%d.%d" % (major, minor)
        if itype == 4:
            fail("a differencing VDI: its unallocated blocks are in its parent (%s), which this does not chain" % self.parent_uuid)
        if self.block_size == 0 or self.blocks == 0 or self.blocks * self.block_size < self.size:
            fail("the VDI header's geometry does not add up: %d blocks of %d bytes for a %d-byte disk" % (self.blocks, self.block_size, self.size))
        if self.blocks > (1 << 28):
            fail("the VDI header claims %d blocks; that is not a disk this reads" % self.blocks)
        raw = host.read(at + self.off_blocks, self.blocks * 4)
        self.bmap = struct.unpack("<%dI" % self.blocks, raw)
        self.zero_bytes_read = 0

    def block_counts(self):
        stride = self.block_size + self.extra
        free = sum(1 for m in self.bmap if m == BLOCK_FREE)
        zero = sum(1 for m in self.bmap if m == BLOCK_ZERO)
        mapped = [m for m in self.bmap if m < BLOCK_ZERO]
        beyond = sum(1 for m in mapped if self.at + self.off_data + (m + 1) * stride > self.host.size)
        return {"allocated_in_map": len(mapped), "free": free, "zero": zero, "past_end_of_host": beyond, "distinct_data_slots": len(set(mapped))}

    def read(self, off, n):
        if off < 0 or off + n > self.size:
            raise IOError("guest read at %d+%d is past the %d-byte disk" % (off, n, self.size))
        out = bytearray()
        while n:
            vi, within = divmod(off, self.block_size)
            take = min(n, self.block_size - within)
            m = self.bmap[vi]
            if m >= BLOCK_ZERO:
                out += bytes(take)
                self.zero_bytes_read += take
            else:
                out += self.host.read(self.at + self.off_data + m * (self.block_size + self.extra) + self.extra + within, take)
            off += take
            n -= take
        return bytes(out)


def parse_runs():
    """The data runs, from runs or runs_file: [lcn, clusters] or {lcn, clusters},
    lcn null (or "sparse") for a sparse run; a file is JSON (a list, or an
    object with runs) or one "lcn clusters" pair per line."""
    given, source = args.get("runs"), None
    if args.get("runs_file"):
        if given:
            fail("pass runs or runs_file, not both")
        source = args["runs_file"]
        if not os.path.isfile(source):
            fail("no such runs_file: %s" % source)
        text = open(source, encoding="utf-8", errors="replace").read()
        try:
            given = json.loads(text)
        except ValueError:
            given = []
            for n, line in enumerate(text.splitlines(), 1):
                line = line.split("#", 1)[0].strip()
                if not line:
                    continue
                parts = re.split(r"[\s,;:]+", line)
                if len(parts) != 2:
                    fail("runs_file line %d is not \"lcn clusters\"" % n, line=line)
                given.append(parts)
        if isinstance(given, dict):
            given = given.get("runs")
    if given is None:
        return None
    if not isinstance(given, list) or not given:
        fail("runs must be a non-empty list of [lcn, clusters] or {lcn, clusters}")
    def number(v):
        if isinstance(v, str) and re.fullmatch(r"\s*\d+\s*", v):
            return int(v)
        return v

    runs = []
    for i, r in enumerate(given):
        if isinstance(r, dict):
            lcn, clusters = r.get("lcn"), r.get("clusters")
        elif isinstance(r, (list, tuple)) and len(r) == 2:
            lcn, clusters = r
        else:
            fail("run %d is not [lcn, clusters] or {lcn, clusters}" % i, run=r)
        if isinstance(lcn, str) and lcn.strip().lower() in ("sparse", "null", "none", "-"):
            lcn = None
        lcn, clusters = number(lcn), number(clusters)
        good_lcn = lcn is None or (isinstance(lcn, int) and not isinstance(lcn, bool) and lcn >= 0)
        good_count = isinstance(clusters, int) and not isinstance(clusters, bool) and clusters >= 1
        if not (good_lcn and good_count):
            fail("run %d is not an lcn (a whole number, or null for a sparse run) and a number of clusters" % i, run=r)
        runs.append((lcn, clusters))
    return runs


def open_outer():
    path = args.get("image")
    if not isinstance(path, str) or not path:
        fail("need image: the E01 or raw image the VDI lies in")
    if not os.path.isfile(path):
        fail("image not found: %s" % path)
    with open(path, "rb") as fh:
        magic = fh.read(8)
    if magic.startswith(b"EVF"):
        try:
            return EwfImage(path)
        except (IOError, OSError) as e:
            fail("libewf could not open %s: %s" % (path, str(e).strip()))
    if magic.startswith(b"LVF"):
        fail("an L01 holds logical files, not a disk: find the VDI's bytes another way")
    return RawImage(path)


def iso(t):
    if not t:
        return None
    try:
        return datetime.fromtimestamp(t, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except (OverflowError, OSError, ValueError):
        return None


def guest_image(disk):
    pytsk3 = load_pytsk3()

    class Guest(pytsk3.Img_Info):
        def __init__(self):
            super().__init__(url="", type=pytsk3.TSK_IMG_TYPE_EXTERNAL)

        def get_size(self):
            return disk.size

        def read(self, off, n):
            if off >= disk.size:
                return b""
            return disk.read(off, min(n, disk.size - off))

        def close(self):
            pass

    return pytsk3, Guest()


def fs_type_name(pytsk3, ftype):
    """TSK's file system type as its name (FAT12, NTFS, EXT4), not its number."""
    for n in dir(pytsk3):
        if n.startswith("TSK_FS_TYPE_") and not n.endswith(("_DETECT", "_ENUM")) and isinstance(getattr(pytsk3, n), int) and getattr(pytsk3, n) == int(ftype):
            return n[len("TSK_FS_TYPE_"):]
    return str(ftype)


def meta_kind(pytsk3, t):
    kinds = {"DIR": "dir", "REG": "file", "LNK": "link", "VIRT": "virtual", "VIRT_DIR": "virtual_dir"}
    for k, v in kinds.items():
        if int(t) == int(getattr(pytsk3, "TSK_FS_META_TYPE_" + k, -1)):
            return v
    return "other"


def file_systems(pytsk3, img):
    """The guest's partitions, each with the file system in it when TSK reads one."""
    found = []
    try:
        vol = pytsk3.Volume_Info(img)
    except (IOError, OSError, RuntimeError):
        vol = None
    parts = []
    if vol is None:
        parts.append({"start": 0, "length": img.get_size() // 512, "description": "no partition table: the whole disk", "sector_size": 512})
    else:
        for p in vol:
            desc = p.desc.decode("utf-8", "replace") if isinstance(p.desc, bytes) else str(p.desc)
            parts.append({"addr": int(p.addr), "start": int(p.start), "length": int(p.len), "description": desc, "sector_size": int(vol.info.block_size), "allocated": bool(int(p.flags) & int(pytsk3.TSK_VS_PART_FLAG_ALLOC))})
    for d in parts:
        if d.get("allocated") is False:
            found.append(d)
            continue
        try:
            fs = pytsk3.FS_Info(img, offset=d["start"] * d["sector_size"])
            d["file_system"] = fs_type_name(pytsk3, fs.info.ftype)
            d["block_size"] = int(fs.info.block_size)
        except (IOError, OSError, RuntimeError) as e:
            d["file_system"] = None
            d["fs_error"] = str(e).strip().splitlines()[0] if str(e).strip() else type(e).__name__
        found.append(d)
    return found


def pick_fs(pytsk3, img):
    parts = file_systems(pytsk3, img)
    want = whole("partition")
    with_fs = [p for p in parts if p.get("file_system")]
    if want is not None:
        hit = [p for p in parts if p["start"] == want]
        if not hit or not hit[0].get("file_system"):
            fail("no file system at partition %d (a start sector, as info lists them)" % want, partitions=parts)
        p = hit[0]
    elif len(with_fs) == 1:
        p = with_fs[0]
    elif not with_fs:
        fail("no file system TSK reads in the guest disk", partitions=parts)
    else:
        fail("several file systems in the guest disk; pass partition= its start sector", partitions=parts)
    return p, pytsk3.FS_Info(img, offset=p["start"] * p["sector_size"])


def entry_record(pytsk3, e, parent):
    name = e.info.name.name.decode("utf-8", "replace") if e.info.name and e.info.name.name else "?"
    meta = e.info.meta
    kind = "other"
    if meta is not None:
        kind = meta_kind(pytsk3, meta.type)
    elif e.info.name and int(e.info.name.type) == int(pytsk3.TSK_FS_NAME_TYPE_DIR):
        kind = "dir"
    rec = {
        "path": (parent.rstrip("/") + "/" + name) if parent != "/" else "/" + name,
        "name": name,
        "type": kind,
        "inode": int(meta.addr) if meta is not None else (int(e.info.name.meta_addr) if e.info.name else None),
        "size": int(meta.size) if meta is not None else None,
        "allocated": bool(int(e.info.name.flags) & int(pytsk3.TSK_FS_NAME_FLAG_ALLOC)) if e.info.name else None,
    }
    if meta is not None:
        for k in ("mtime", "atime", "ctime", "crtime"):
            rec[k] = iso(getattr(meta, k, 0))
    return rec


args = json.load(sys.stdin)
if not isinstance(args, dict):
    fail("arguments must be a JSON object")
action = args.get("action") or "info"
if action not in ("info", "ls", "extract", "read"):
    fail("action must be info, ls, extract or read", got=action)
outer = open_outer()
offset = whole("offset", 0)
cluster_size = whole("cluster_size", 4096, 1)
vdi_offset = whole("vdi_offset", 0)
runs = parse_runs()
volume = Slice(outer, offset * 512)
if offset * 512 >= outer.size:
    fail("offset %d (sectors of 512 bytes) is past the end of the %d-byte image" % (offset, outer.size))
host = RunFile(volume, runs, cluster_size) if runs else volume
try:
    disk = VdiDisk(host, vdi_offset)
except IOError as e:
    fail("the VDI header or block map could not be read: %s" % e, hint="check offset (sectors), cluster_size and the runs")
where = {
    "image": args["image"],
    "image_format": outer.kind,
    "volume_offset_bytes": offset * 512,
    "host": ({"kind": "data runs", "runs": len(runs), "cluster_size": cluster_size, "clusters": sum(c for _l, c in runs), "sparse_clusters": sum(c for lcn, c in runs if lcn is None), "bytes": host.size}
             if runs else {"kind": "contiguous in the volume", "bytes": host.size}),
    "vdi_offset": vdi_offset,
}

if action == "info":
    counts = disk.block_counts()
    result = {"ok": True, **where, "vdi": {
        "text": disk.text, "version": disk.version, "header_size": disk.header_size, "image_type": disk.image_type,
        "flags": disk.flags, "description": disk.description, "disk_size": disk.size, "block_size": disk.block_size,
        "block_extra": disk.extra, "blocks": disk.blocks, "allocated_in_header": disk.allocated_header, **counts,
        "offset_block_map": disk.off_blocks, "offset_data": disk.off_data, "geometry": disk.geometry, "uuid": disk.uuid,
    }}
    if counts["allocated_in_map"] != disk.allocated_header:
        result["note"] = "the header says %d blocks are allocated and the map has %d" % (disk.allocated_header, counts["allocated_in_map"])
    if counts["past_end_of_host"]:
        result["warning"] = "%d allocated blocks lie past the end of the file that holds the VDI (runs incomplete?): reads there fail" % counts["past_end_of_host"]
    if not have_pytsk3():
        result["partitions_error"] = "pytsk3 is not installed: the guest's partitions and file systems are not listed (the disk and mobile images have it)"
        print(json.dumps(result))
        sys.exit(0)
    pytsk3, img = guest_image(disk)
    result["partitions"] = file_systems(pytsk3, img)
    print(json.dumps(result))
    sys.exit(0)

if action == "read":
    at, length = whole("at", 0), whole("length", None, 1)
    if length is None:
        fail("read needs length (bytes) and at (the guest byte offset, default 0)")
    if at + length > disk.size:
        fail("at %d + length %d is past the %d-byte guest disk" % (at, length, disk.size))
    out_path = args.get("output")
    if not out_path and length > INLINE_READ_MAX:
        fail("more than %d bytes go to a file: pass output" % INLINE_READ_MAX)
    digest = hashlib.sha256()
    dest = resolve_output(out_path) if out_path else None
    inline = bytearray()
    try:
        fh = None
        if dest:
            dest.parent.mkdir(parents=True, exist_ok=True)
            fh = open(dest, "wb")
        pos, left = at, length
        while left:
            chunk = disk.read(pos, min(CHUNK, left))
            digest.update(chunk)
            if fh:
                fh.write(chunk)
            else:
                inline += chunk
            pos += len(chunk)
            left -= len(chunk)
        if fh:
            fh.close()
    except IOError as e:
        fail(str(e), **where)
    result = {"ok": True, **where, "at": at, "length": length, "sha256": digest.hexdigest(),
              "zeros_from_unallocated_blocks": disk.zero_bytes_read, "zeros_from_sparse_runs": getattr(host, "sparse_bytes_read", 0)}
    if dest:
        result["output"] = out_path
    else:
        result["hex"] = inline.hex()
    print(json.dumps(result))
    sys.exit(0)

pytsk3, img = guest_image(disk)
part, fs = pick_fs(pytsk3, img)
where["partition"] = {k: part[k] for k in ("start", "length", "description", "file_system") if k in part}

if action == "ls":
    path = args.get("path") or "/"
    recursive = bool(args.get("recursive", False))
    limit = whole("limit", 500, 1)
    try:
        top = fs.open_dir(path=path)
    except (IOError, OSError) as e:
        fail("cannot open directory %s in the guest file system: %s" % (path, str(e).strip()), **where)
    page = LosslessPage("nested_vdi", [args.get("image"), offset, runs, cluster_size, vdi_offset, part["start"], path, recursive], limit)
    stack, seen, errors = [(path, top)], set(), []
    while stack:
        parent, d = stack.pop(0)
        for e in d:
            rec = entry_record(pytsk3, e, parent)
            if rec["name"] in (".", ".."):
                continue
            page.add(rec)
            # $OrphanFiles, a virtual directory, is where TSK puts deleted files it found no parent for.
            if recursive and rec["type"] in ("dir", "virtual_dir") and rec["inode"] is not None and rec["inode"] not in seen:
                seen.add(rec["inode"])
                try:
                    stack.append((rec["path"], e.as_directory()))
                except (IOError, OSError, RuntimeError) as err:
                    errors.append({"path": rec["path"], "error": str(err).strip()})
    got = page.finish()
    result = {"ok": True, **where, "path": path, "recursive": recursive, **got, "entries": page.page}
    if errors:
        result["directories_not_read"] = errors
    print(json.dumps(result, ensure_ascii=False))
    sys.exit(0)

# extract
out_path = args.get("output")
if not isinstance(out_path, str) or not out_path:
    fail("extract needs output: where to write the file, under your work directory")
dest = resolve_output(out_path)
try:
    if args.get("inode") is not None:
        f = fs.open_meta(inode=whole("inode"))
    elif args.get("path"):
        f = fs.open(args["path"])
    else:
        fail("extract needs path or inode")
except (IOError, OSError) as e:
    fail("cannot open %s in the guest file system: %s" % (args.get("path") or args.get("inode"), str(e).strip()), **where)
meta = f.info.meta
if meta is None:
    fail("that entry has no metadata to read a file from", **where)
if meta_kind(pytsk3, meta.type) in ("dir", "virtual_dir"):
    fail("that is a directory: list it with action=ls", **where)
size = int(meta.size)
digest = hashlib.sha256()
dest.parent.mkdir(parents=True, exist_ok=True)
tmp = dest.with_name(".%s.part" % dest.name)
try:
    with open(tmp, "wb") as fh:
        pos = 0
        while pos < size:
            chunk = f.read_random(pos, min(CHUNK, size - pos))
            if not chunk:
                raise IOError("the file system gave no bytes at %d of %d" % (pos, size))
            fh.write(chunk)
            digest.update(chunk)
            pos += len(chunk)
    os.replace(tmp, dest)
except (IOError, OSError) as e:
    try:
        os.unlink(tmp)
    except OSError:
        pass
    fail("extract failed: %s" % str(e).strip(), **where)
print(json.dumps({"ok": True, **where, "path": args.get("path"), "inode": int(meta.addr), "output": out_path, "size": size, "sha256": digest.hexdigest(),
                  "allocated": bool(int(f.info.name.flags) & int(pytsk3.TSK_FS_NAME_FLAG_ALLOC)) if f.info.name else None,
                  "mtime": iso(meta.mtime), "crtime": iso(getattr(meta, "crtime", 0))}, ensure_ascii=False))
