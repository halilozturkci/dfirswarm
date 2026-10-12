#!/usr/bin/env python3
"""Read an image's layout once, so a swarm does not read it seven times.

Every extract, every listing and every hive in a case is addressed by a volume
offset, and in the measured runs the commonest wasted minutes were spent
rediscovering it or passing it in the wrong unit. mmls prints sectors, the
Sleuth Kit's -o takes sectors, and an agent that multiplies by 512 once gets
nothing back and concludes the image is damaged.

So: run mmls, run fsstat per slot, read the E01's own acquisition record when
there is one, and hand back both the sector offset and the byte offset with the
unit named on each.

What this is: a probe, run through the Sleuth Kit as installed. What it is not:
a proof that there is no partition table, no volume or no encryption. A tool
that could not run, timed out or was refused is `unknown` or `not attempted`,
never "no partition table". A `sector_size` given by the caller is passed to
mmls and fsstat as -b, so the offsets the Sleuth Kit parsed with and the byte
offsets returned here use one unit; it is not arithmetic done afterwards. One
path is read: a split raw set is not assembled, and the note says so when it
sees a first segment. The programs' own output is kept whole in files.
"""
import hashlib
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

TOOL = {"name": "image_layout", "version": 2}
CHILD_TIMEOUT = 120
TOTAL_BUDGET = 270          # seconds, under the manifest's 300
SECTOR_MAX = 65536
VIRTUAL_DISKS = ("vhd", "vhdx", "vmdk", "qcow", "aff")
# The image type img_stat prints for what the Sleuth Kit has a reader for; a container with none is read as "raw" if at all.
TSK_IMAGE_TYPES = {"ewf": "ewf", "vmdk": "vmdk", "vhd": "vhd", "aff": "aff"}


def fail(message, **extra):
    print(json.dumps({"error": message, "tool": TOOL, **extra}))
    raise SystemExit(1)


class Deadline:
    def __init__(self, seconds):
        self.end = time.monotonic() + seconds

    def left(self):
        return self.end - time.monotonic()


def run(argv, deadline):
    """A program's outcome: kind is ok, missing, timeout, refused (it ran and
    exited non-zero), skipped (the time budget was gone) or error. Locale is C
    so the messages parsed below are the ones the Sleuth Kit prints."""
    if not shutil.which(argv[0]):
        return {"kind": "missing", "stdout": "", "stderr": "%s is not on PATH" % argv[0], "code": None}
    budget = min(CHILD_TIMEOUT, deadline.left())
    if budget <= 1:
        return {"kind": "skipped", "stdout": "", "stderr": "not run: the tool's time budget (%ds) was used" % TOTAL_BUDGET, "code": None}
    env = dict(os.environ, LC_ALL="C", LANG="C")
    try:
        p = subprocess.run(argv, capture_output=True, timeout=budget, env=env)
    except subprocess.TimeoutExpired:
        return {"kind": "timeout", "stdout": "", "stderr": "%s timed out after %ds" % (argv[0], budget), "code": None}
    except OSError as exc:
        return {"kind": "error", "stdout": "", "stderr": str(exc), "code": None}
    return {"kind": "ok" if p.returncode == 0 else "refused", "code": p.returncode,
            "stdout": p.stdout.decode("utf-8", "replace"), "stderr": p.stderr.decode("utf-8", "replace").strip()}


def container_of(path):
    """Name the container from its first bytes (and, for a fixed VHD, its last
    512), not from its extension. (name, basis): the basis says how sure that is."""
    try:
        size = os.path.getsize(path)
        with open(path, "rb") as fh:
            head = fh.read(512)
            tail = b""
            if size >= 512:
                fh.seek(size - 512)
                tail = fh.read(512)
    except OSError as exc:
        fail("cannot read the image", path=path, reason=str(exc))
    if head[:3] in (b"EVF", b"LVF"):
        return "ewf", "signature at offset 0"          # E01/Ex01/L01
    if head[:3] == b"AFF":
        return "aff", "signature at offset 0"          # AFF1; AFF4 is a zip container and is not named from its head
    if head[:4] == b"QFI\xfb":
        return "qcow", "signature at offset 0"
    if head[:8] == b"vhdxfile":
        return "vhdx", "signature at offset 0"
    if head[:4] == b"KDMV" or head.startswith(b"# Disk DescriptorFile"):
        return "vmdk", "signature at offset 0"
    if head[:8] == b"conectix":
        return "vhd", "footer copy at offset 0 (a dynamic or differencing disk)"
    if tail[:8] == b"conectix":
        return "vhd", "footer in the last 512 bytes (a fixed disk)"
    return "raw", "no container signature matched: the bytes of a disk or volume, or a format this tool does not know"


SLOT = re.compile(
    r"^(?P<slot>\d{3}):\s+(?P<table>\S+)\s+(?P<start>\d+)\s+(?P<end>\d+)\s+(?P<len>\d+)\s+(?P<desc>.*\S)\s*$"
)


def parse_mmls(text):
    sector = 512
    m = re.search(r"Units are in (\d+)-byte sectors", text)
    if m:
        sector = int(m.group(1))
    slots = []
    for line in text.splitlines():
        m = SLOT.match(line.strip())
        if not m:
            continue
        desc = m.group("desc")
        slots.append({
            "slot": m.group("slot"),
            "start_sector": int(m.group("start")),
            "length_sectors": int(m.group("len")),
            "description": desc,
            # The table column says what a row is ("-------" a gap, "Meta" a table area, anything else an entry);
            # the description is a partition's own name in a GPT and says nothing of the sort.
            "allocated": m.group("table") != "-------" and m.group("table").lower() != "meta",
        })
    return sector, slots


# [ \t]* after the colon, never \s*: a field with no value must not take the next line for its value.
FSSTAT_FIELDS = (
    ("fs_type", re.compile(r"^File System Type:[ \t]*(\S.*?)[ \t]*$", re.M)),
    # NTFS and exFAT print a serial number, FAT a volume ID.
    ("volume_serial", re.compile(r"^Volume (?:Serial Number|ID):[ \t]*(\S.*?)[ \t]*$", re.M)),
    # FAT names the label's source in brackets (Boot Sector, Root Directory); ext and NTFS call it a name.
    ("volume_label", re.compile(r"^Volume (?:Label|Name)(?: \([^)\n]*\))?:[ \t]*(\S.*?)[ \t]*$", re.M)),
    ("cluster_size", re.compile(r"^Cluster Size:[ \t]*(\d+)", re.M)),
    ("sector_size", re.compile(r"^Sector Size:[ \t]*(\d+)", re.M)),
    ("total_range", re.compile(r"^Total (?:Cluster|Sector|Inode) Range:[ \t]*(\S.*?)[ \t]*$", re.M)),
    ("last_mounted", re.compile(r"^Last Mounted (?:at|on):[ \t]*(\S.*?)[ \t]*$", re.M)),
)


def sector_args(unit, forced):
    """-b for every Sleuth Kit call: the caller's sector size, or the unit mmls
    printed its offsets in when that is not the default, so one unit holds."""
    size = forced or (unit if unit and unit != 512 else None)
    return ["-b", str(size)] if size else []


class Keep:
    """The whole output of each program, in a file, named in the result."""

    def __init__(self, image):
        self.digest = hashlib.sha256(os.path.abspath(image).encode()).hexdigest()[:12]
        job, out = os.environ.get("JOB_ID"), os.environ.get("OUT")
        if job and out:
            self.dir = Path(out) / "tool-output"
            self.shown = "store/jobs/%s/out/tool-output/" % re.sub(r"[^A-Za-z0-9_.-]", "_", job)
        else:
            agent = re.sub(r"[^A-Za-z0-9_.-]", "_", os.environ.get("AGENT_ID") or "tool")
            self.dir = Path("work") / agent / "tool-output"
            self.shown = str(self.dir) + "/"
        self.files, self.error = {}, None

    def save(self, label, text, argv=None):
        # Keyed by the command as well as the image: the same program run with another sector size is another file.
        key = hashlib.sha256(" ".join(argv or [label]).encode("utf-8", "replace")).hexdigest()[:8]
        name = "image_layout-%s-%s-%s.txt" % (self.digest, label, key)
        try:
            self.dir.mkdir(parents=True, exist_ok=True)
            fd, tmp = tempfile.mkstemp(dir=self.dir, prefix=".image_layout-")
            with os.fdopen(fd, "w", encoding="utf-8", errors="replace") as fh:
                fh.write(text)
            os.replace(tmp, self.dir / name)
            self.files[label] = self.shown + name
        except OSError as exc:
            self.error = "the programs' whole output could not be kept (%s: %s)" % (self.dir, exc.strerror or exc)


def describe_fs(image, offset, unit, forced, deadline, keep, label):
    argv = ["fsstat"] + sector_args(unit, forced) + (["-o", str(offset)] if offset is not None else []) + [image]
    res = run(argv, deadline)
    if res["stdout"] or res["stderr"]:
        keep.save("fsstat-" + label, "$ %s\n%s%s" % (shlex.join(argv), res["stdout"], ("\n[stderr]\n" + res["stderr"]) if res["stderr"] else ""), argv)
    if res["kind"] != "ok":
        why = res["stderr"].splitlines()[-1] if res["stderr"] else "fsstat returned nothing"
        return {"readable": None if res["kind"] in ("missing", "timeout", "skipped", "error") else False,
                "outcome": res["kind"], "why": why, "command": shlex.join(argv)}
    found = {"readable": True, "outcome": "read", "command": shlex.join(argv)}
    for key, pattern in FSSTAT_FIELDS:
        m = pattern.search(res["stdout"])
        if m:
            found[key] = int(m.group(1)) if key in ("cluster_size", "sector_size") else m.group(1)
    return found


ACQUISITION = (
    ("acquired_by", re.compile(r"^[ \t]*Examiner name:[ \t]*(\S.*?)[ \t]*$", re.M)),
    ("case_number", re.compile(r"^[ \t]*Case number:[ \t]*(\S.*?)[ \t]*$", re.M)),
    ("description", re.compile(r"^[ \t]*Description:[ \t]*(\S.*?)[ \t]*$", re.M)),
    ("acquired_at", re.compile(r"^[ \t]*Acquisition date:[ \t]*(\S.*?)[ \t]*$", re.M)),
    ("system_date", re.compile(r"^[ \t]*System date:[ \t]*(\S.*?)[ \t]*$", re.M)),
    ("imager", re.compile(r"^[ \t]*Acquisition software:[ \t]*(\S.*?)[ \t]*$", re.M)),
    ("media_size", re.compile(r"^[ \t]*Media size:[ \t]*(\S.*?)[ \t]*$", re.M)),
    ("bytes_per_sector", re.compile(r"^[ \t]*Bytes per sector:[ \t]*(\d+)", re.M)),
    ("md5", re.compile(r"^[ \t]*MD5:[ \t]*([0-9a-fA-F]+)", re.M)),
    ("sha1", re.compile(r"^[ \t]*SHA1:[ \t]*([0-9a-fA-F]+)", re.M)),
    ("sha256", re.compile(r"^[ \t]*SHA256:[ \t]*([0-9a-fA-F]+)", re.M)),
)


def acquisition_record(image, deadline, keep):
    res = run(["ewfinfo", image], deadline)
    if res["stdout"] or res["stderr"]:
        keep.save("ewfinfo", "$ ewfinfo %s\n%s%s" % (shlex.quote(image), res["stdout"], ("\n[stderr]\n" + res["stderr"]) if res["stderr"] else ""), ["ewfinfo", image])
    if res["kind"] != "ok":
        return {"read": False, "outcome": res["kind"], "why": res["stderr"].splitlines()[-1] if res["stderr"] else "ewfinfo returned nothing"}
    rec = {"read": True}
    for key, pattern in ACQUISITION:
        m = pattern.search(res["stdout"])
        if m:
            rec[key] = m.group(1)
    return rec


def split_raw_note(image):
    """A first segment of a split raw set (x.001 with x.002 beside it)."""
    m = re.match(r"^(.*)\.(0*1)$", image) or re.match(r"^(.*)\.(0+)$", image)       # .001 first, or .000 (some imagers start there)
    if m:
        digits = m.group(2)
        nxt = m.group(1) + "." + (digits[:-1] + ("2" if digits.endswith("1") else "1"))
        if os.path.isfile(nxt):
            return ("%s has a second segment beside it (%s). This tool reads one path: the offsets and "
                    "volumes below cover that segment alone, not the whole image. Assemble the set in order "
                    "with a reader that supports it before relying on them." % (os.path.basename(image), os.path.basename(nxt)))
    return None


def main():
    try:
        args = json.load(sys.stdin)
    except ValueError as exc:
        fail("arguments are not valid JSON", reason=str(exc))
    if not isinstance(args, dict):
        fail("arguments are a JSON object")

    image = args.get("image")
    if not isinstance(image, str) or not image:
        fail("image is required: the path to a raw or E01 image")
    if not os.path.isfile(image):
        fail("no such image", image=image)

    forced = args.get("sector_size")
    if forced is not None and (not isinstance(forced, int) or isinstance(forced, bool)
                               or forced < 512 or forced > SECTOR_MAX or forced % 512):
        fail("sector_size must be a multiple of 512 from 512 to %d (the Sleuth Kit's -b takes no other)" % SECTOR_MAX, sector_size=forced)

    # A name that begins with "-" would be read by every Sleuth Kit program as an option: "./" makes it a path.
    arg = "./" + image if image.startswith("-") else image
    deadline = Deadline(TOTAL_BUDGET)
    keep = Keep(image)
    container, basis = container_of(image)
    out = {
        "tool": TOOL,
        "image": image,
        "bytes": os.path.getsize(image),
        "container": container,
        "container_basis": basis,
        "notes": [],
    }
    split = split_raw_note(image)
    if split:
        out["notes"].append(split)
    if out["container"] == "ewf":
        out["acquisition"] = acquisition_record(arg, deadline, keep)
        if out["acquisition"].get("read"):
            out["notes"].append(
                "The digests under 'acquisition' are the imager's, over what it acquired (a disk, a volume or "
                "a set of files: the acquisition record says which). They are not the digest of this "
                "container, and not of the volume inside it."
            )

    probe = ["mmls"] + (["-b", str(forced)] if forced else []) + [arg]
    res = run(probe, deadline)
    keep.save("mmls", "$ %s\n%s%s" % (shlex.join(probe), res["stdout"], ("\n[stderr]\n" + res["stderr"]) if res["stderr"] else ""), probe)
    out["mmls_command"] = shlex.join(probe)
    opened_as = None
    if res["kind"] == "ok" and out["container"] != "raw":
        # mmls succeeding says the Sleuth Kit read bytes, not which reader it used: a VHD or a QCOW2 TSK cannot open is read as
        # a raw disk, and the offsets then belong to the container's bytes and mean nothing for the disk inside. img_stat names the
        # image type TSK opened it as.
        st_argv = ["img_stat"] + (["-b", str(forced)] if forced else []) + [arg]
        st = run(st_argv, deadline)
        if st["stdout"] or st["stderr"]:
            keep.save("img_stat", "$ %s\n%s%s" % (shlex.join(st_argv), st["stdout"], ("\n[stderr]\n" + st["stderr"]) if st["stderr"] else ""), st_argv)
        m = re.search(r"^Image Type:[ \t]*(\S+)", st["stdout"], re.M)
        opened_as = m.group(1).lower() if m else None
        out["image_type_opened_by_sleuth_kit"] = opened_as
        expected = TSK_IMAGE_TYPES.get(out["container"])
        if opened_as is not None and opened_as != expected:
            out["partition_table"] = "unknown"
            out["partition_table_basis"] = ("mmls printed a table, but img_stat says the Sleuth Kit opened this %s container as %s%s: its offsets belong to "
                                            "the container's bytes, not to the disk inside, and are not given here" % (out["container"], opened_as, " (it has no reader for %s)" % out["container"] if not expected else ""))
            out["sector_size"] = forced or 512
            out["sector_size_source"] = "given by the caller (-b)" if forced else "the default: the offsets were not used"
            out["partitions"] = []
            out["volumes_readable"] = out["volumes_refused"] = out["volumes_not_attempted"] = 0
            out["notes"].append(
                "The Sleuth Kit opened this %s container as %s, so no offset or file system is read from it: convert or attach it (qemu-img, a "
                "mount of the virtual disk) and run this tool on the result, or use a reader of the container." % (out["container"], opened_as))
            res = {"kind": "container-not-opened", "stdout": "", "stderr": "", "code": None}
    if res["kind"] == "container-not-opened":
        pass
    elif res["kind"] == "ok":
        if out["container"] in VIRTUAL_DISKS:
            out["notes"].append(
                ("The Sleuth Kit opened this %s container as %s (img_stat). " % (out["container"], opened_as) if opened_as else
                 "img_stat did not say which image type the Sleuth Kit opened this %s container as, so that it read the container and not its raw bytes "
                 "is not confirmed. " % out["container"])
                + "The offsets below are sectors in the virtual disk, valid for Sleuth Kit commands against this container."
            )
        unit, slots = parse_mmls(res["stdout"])
        if forced and unit != forced:
            out["notes"].append("sector_size %d was given, but mmls printed its offsets in %d-byte sectors: "
                                "the offsets below are in %d-byte sectors." % (forced, unit, unit))
        out["sector_size"] = unit
        out["sector_size_source"] = "given by the caller (-b)" if forced else "the units line of mmls"
        out["partition_table"] = True
        parts = []
        for n, slot in enumerate(slots):
            entry = dict(slot)
            entry["offset_sectors"] = slot["start_sector"]
            entry["offset_bytes"] = slot["start_sector"] * unit
            entry["length_bytes"] = slot["length_sectors"] * unit
            if slot["allocated"]:
                entry["filesystem"] = describe_fs(arg, slot["start_sector"], unit, forced, deadline, keep, "p%d" % slot["start_sector"])
            parts.append(entry)
        out["partitions"] = parts
        fs = [p["filesystem"] for p in parts if "filesystem" in p]
        out["volumes_readable"] = sum(1 for f in fs if f["readable"] is True)
        out["volumes_refused"] = sum(1 for f in fs if f["readable"] is False)
        out["volumes_not_attempted"] = sum(1 for f in fs if f["readable"] is None)
        if out["volumes_refused"]:
            out["notes"].append(
                "%d allocated partition(s) have no file system fsstat read at their table offset. Not a "
                "diagnosis: the sector size, a mapping layer (LVM, RAID, Storage Spaces), a file system or "
                "feature this build does not read, damage and encryption each look like this. Test them "
                "in that order of cost: evidence/imaging, then filesystem/encrypted." % out["volumes_refused"]
            )
        if out["volumes_not_attempted"]:
            out["notes"].append(
                "%d allocated partition(s) were not examined (fsstat missing, timed out or the tool's time budget "
                "ran out): their state is unknown." % out["volumes_not_attempted"]
            )
        big_gaps = [p for p in parts if not p["allocated"] and p["length_bytes"] > 64 * 1024 * 1024]
        if big_gaps:
            out["notes"].append(
                "%d unallocated gap(s) larger than 64 MB. A gap can be unused space or the remains of a "
                "removed partition entry; its content is the evidence for either, not its size." % len(big_gaps)
            )
    else:
        if out["container"] in VIRTUAL_DISKS and res["kind"] == "refused":
            out["notes"].append(
                "The Sleuth Kit did not open this %s container. Inspect it with qemu-img; "
                "conversion to raw or attachment may be required before deriving offsets."
                % out["container"]
            )
        # mmls ran and found no table it recognises (exit 1, no complaint of its own):
        # that is a result about the bytes at that sector size. Anything else (a missing
        # program, a timeout, an error opening the image) says nothing about the image.
        # Only mmls saying so counts. An exit 1 with nothing said is not the same: the image may not have opened
        # at all, so img_stat is asked whether the Sleuth Kit opens it, and only then is silence taken for "no table".
        recognised_none = res["kind"] == "refused" and bool(
            re.search(r"cannot determine partition type|unknown partition", res["stderr"], re.I))
        silent_basis = None
        if res["kind"] == "refused" and not res["stderr"]:
            opened = run(["img_stat"] + (["-b", str(forced)] if forced else []) + [arg], deadline)
            if opened["stdout"] or opened["stderr"]:
                keep.save("img_stat", "$ img_stat %s\n%s%s" % (shlex.quote(arg), opened["stdout"], ("\n[stderr]\n" + opened["stderr"]) if opened["stderr"] else ""), ["img_stat", arg])
            if opened["kind"] == "ok":
                recognised_none = True
                silent_basis = "mmls exited %s with nothing to say, and img_stat opens the image" % res["code"]
            else:
                silent_basis = "mmls exited %s with nothing to say, and img_stat did not open the image (%s)" % (res["code"], opened["kind"])
        out["sector_size"] = forced or 512
        out["sector_size_source"] = "given by the caller (-b)" if forced else "the default: mmls printed no units"
        if recognised_none:
            out["partition_table"] = False
            out["partition_table_basis"] = ("mmls found no partition table it recognises%s. That does not show the image has none: "
                                            "a table type the Sleuth Kit does not read, a damaged one and a wrong sector size look the same."
                                            % (" at sector size %d" % forced if forced else ""))
            if silent_basis:
                out["partition_table_basis"] += " (%s)" % silent_basis
        else:
            out["partition_table"] = "unknown"
            out["partition_table_basis"] = "mmls could not tell (%s)" % (silent_basis or res["kind"])
            out["mmls_error"] = res["stderr"].splitlines()[-1] if res["stderr"] else "mmls returned nothing"
            out["notes"].append("mmls did not run to a result (%s: %s); nothing here shows whether the image has a "
                                "partition table." % (res["kind"], out["mmls_error"]))
        whole = describe_fs(arg, None, forced, forced, deadline, keep, "whole")
        out["partitions"] = [{
            "slot": "—",
            "description": "the whole image, probed with no partition table"
            if out["partition_table"] is False else "the whole image, probed because the partition table could not be read",
            "offset_sectors": 0,
            "offset_bytes": 0,
            "allocated": True,
            "filesystem": whole,
        }]
        out["volumes_readable"] = 1 if whole.get("readable") is True else 0
        out["volumes_refused"] = 1 if whole.get("readable") is False else 0
        out["volumes_not_attempted"] = 1 if whole.get("readable") is None else 0
        if whole.get("readable") is True and out["partition_table"] is False:
            out["notes"].append(
                "No partition table recognised, and a file system at offset 0: run the toolkit with no -o "
                "at all. mmls finding no table here is the expected answer, not a broken image."
            )
        elif whole.get("readable") is False:
            out["notes"].append(
                "Neither a partition table nor a file system at offset 0 was read. Check the container type "
                "above, the sector size and the image's size against the acquisition record first; "
                "filesystem/encrypted lists what else produces this, encryption among them."
            )

    ready = [p for p in out["partitions"] if p.get("filesystem", {}).get("readable") is True]
    b = sector_args(out["sector_size"], forced)
    flag = (" ".join(b) + " ") if b else ""
    out["use"] = [
        {
            "offset_sectors": p["offset_sectors"],
            "fs_type": p["filesystem"].get("fs_type"),
            "example": "fls -r %s-o %d %s" % (flag, p["offset_sectors"], shlex.quote(arg))
            if out["partition_table"] is True else "fls -r %s%s" % (flag, shlex.quote(arg)),
        }
        for p in ready
    ]
    out["raw_outputs"] = keep.files
    if keep.error:
        out["raw_outputs_error"] = keep.error
    out["not_measured"] = ("Snapshots, backing files and the other segments of a split set are not read; "
                           "a file system fsstat reads here is not shown to be intact or complete, and an "
                           "encrypted volume looks like any other it cannot read.")
    print(json.dumps(out, indent=2))


if __name__ == "__main__":
    main()
