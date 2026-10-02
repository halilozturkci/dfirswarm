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
"""
import json
import os
import re
import shutil
import subprocess
import sys

TIMEOUT = 120


def fail(message, **extra):
    print(json.dumps({"error": message, **extra}))
    raise SystemExit(1)


def run(argv):
    """Return (ok, stdout, stderr). A missing binary is a result, not a crash."""
    if not shutil.which(argv[0]):
        return False, "", "%s is not on PATH" % argv[0]
    try:
        p = subprocess.run(argv, capture_output=True, text=True, timeout=TIMEOUT)
    except subprocess.TimeoutExpired:
        return False, "", "%s timed out after %ds" % (argv[0], TIMEOUT)
    except OSError as exc:
        return False, "", str(exc)
    return p.returncode == 0, p.stdout, p.stderr.strip()


def container_of(path):
    """Name the container from its first bytes, not from its extension."""
    try:
        with open(path, "rb") as fh:
            head = fh.read(16)
    except OSError as exc:
        fail("cannot read the image", path=path, reason=str(exc))
    if head[:3] == b"EVF" or head[:3] == b"LVF":
        return "ewf"          # E01/Ex01/L01
    if head[:3] == b"AFF":
        return "aff"            # AFF1; AFF4 is a zip container and is not named from its head
    if head[:4] == b"QFI\xfb":
        return "qcow"
    if head[:8] == b"vhdxfile":
        return "vhdx"
    if head[:3] == b"KDM":
        return "vmdk"
    if head[:4] == b"conectix":
        return "vhd"
    return "raw"


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
            "allocated": not desc.lower().startswith("unallocated")
            and "meta" not in m.group("table").lower(),
        })
    return sector, slots


FSSTAT_FIELDS = (
    ("fs_type", re.compile(r"^File System Type:\s*(.+?)\s*$", re.M)),
    ("volume_serial", re.compile(r"^Volume Serial Number:\s*(.+?)\s*$", re.M)),
    ("volume_label", re.compile(r"^Volume (?:Label|Name)(?: \(from \S+\))?:\s*(.+?)\s*$", re.M)),
    ("cluster_size", re.compile(r"^Cluster Size:\s*(\d+)", re.M)),
    ("sector_size", re.compile(r"^Sector Size:\s*(\d+)", re.M)),
    ("total_range", re.compile(r"^Total (?:Cluster|Sector|Inode) Range:\s*(.+?)\s*$", re.M)),
    ("last_mounted", re.compile(r"^Last Mounted (?:at|on):\s*(.+?)\s*$", re.M)),
)


def describe_fs(image, offset):
    argv = ["fsstat"] + (["-o", str(offset)] if offset is not None else []) + [image]
    ok, out, err = run(argv)
    if not ok:
        return {"readable": False, "why": err.splitlines()[-1] if err else "fsstat returned nothing"}
    found = {"readable": True}
    for key, pattern in FSSTAT_FIELDS:
        m = pattern.search(out)
        if m:
            found[key] = int(m.group(1)) if key in ("cluster_size", "sector_size") else m.group(1)
    return found


ACQUISITION = (
    ("acquired_by", re.compile(r"^\s*Examiner name:\s*(.+?)\s*$", re.M)),
    ("case_number", re.compile(r"^\s*Case number:\s*(.+?)\s*$", re.M)),
    ("description", re.compile(r"^\s*Description:\s*(.+?)\s*$", re.M)),
    ("acquired_at", re.compile(r"^\s*Acquisition date:\s*(.+?)\s*$", re.M)),
    ("system_date", re.compile(r"^\s*System date:\s*(.+?)\s*$", re.M)),
    ("imager", re.compile(r"^\s*Acquisition software:\s*(.+?)\s*$", re.M)),
    ("media_size", re.compile(r"^\s*Media size:\s*(.+?)\s*$", re.M)),
    ("bytes_per_sector", re.compile(r"^\s*Bytes per sector:\s*(\d+)", re.M)),
    ("md5", re.compile(r"^\s*MD5:\s*([0-9a-fA-F]+)", re.M)),
    ("sha1", re.compile(r"^\s*SHA1:\s*([0-9a-fA-F]+)", re.M)),
    ("sha256", re.compile(r"^\s*SHA256:\s*([0-9a-fA-F]+)", re.M)),
)


def acquisition_record(image):
    ok, out, err = run(["ewfinfo", image])
    if not ok:
        return {"read": False, "why": err.splitlines()[-1] if err else "ewfinfo returned nothing"}
    rec = {"read": True}
    for key, pattern in ACQUISITION:
        m = pattern.search(out)
        if m:
            rec[key] = m.group(1)
    return rec


def main():
    try:
        args = json.load(sys.stdin)
    except ValueError as exc:
        fail("arguments are not valid JSON", reason=str(exc))

    image = args.get("image")
    if not isinstance(image, str) or not image:
        fail("image is required: the path to a raw or E01 image")
    if not os.path.isfile(image):
        fail("no such image", image=image)

    forced = args.get("sector_size")
    if forced is not None and (not isinstance(forced, int) or isinstance(forced, bool) or forced < 1):
        fail("sector_size must be a positive integer", sector_size=forced)

    out = {
        "image": image,
        "bytes": os.path.getsize(image),
        "container": container_of(image),
        "notes": [],
    }
    if out["container"] == "ewf":
        out["acquisition"] = acquisition_record(image)
        if out["acquisition"].get("read"):
            out["notes"].append(
                "The digests under 'acquisition' are the imager's, over the source device. "
                "They are not the digest of this container, and not of the volume inside it."
            )

    ok, mmls_out, mmls_err = run(["mmls", image])
    if ok:
        if out["container"] in ("vhd", "vhdx", "vmdk", "qcow", "aff"):
            out["notes"].append(
                "The Sleuth Kit opened this %s container directly. The offsets below are "
                "sectors in the virtual disk and are valid for Sleuth Kit commands against "
                "this container; convert it only for a tool that cannot open the container."
                % out["container"]
            )
        sector, slots = parse_mmls(mmls_out)
        if forced:
            sector = forced
        out["sector_size"] = sector
        out["partition_table"] = True
        parts = []
        for slot in slots:
            entry = dict(slot)
            entry["offset_sectors"] = slot["start_sector"]
            entry["offset_bytes"] = slot["start_sector"] * sector
            entry["length_bytes"] = slot["length_sectors"] * sector
            if slot["allocated"]:
                entry["filesystem"] = describe_fs(image, slot["start_sector"])
            parts.append(entry)
        out["partitions"] = parts
        readable = [p for p in parts if p.get("filesystem", {}).get("readable")]
        out["volumes_readable"] = len(readable)
        unreadable = [p for p in parts if p.get("allocated") and not p.get("filesystem", {}).get("readable")]
        if unreadable:
            out["notes"].append(
                "%d allocated partition(s) have no readable file system at their table offset. "
                "That is a logical volume, an encrypted volume or a damaged one, and it is usually "
                "the case's first real question: see filesystem/encrypted." % len(unreadable)
            )
        big_gaps = [p for p in parts if not p["allocated"] and p["length_bytes"] > 64 * 1024 * 1024]
        if big_gaps:
            out["notes"].append(
                "%d unallocated gap(s) larger than 64 MB. A deleted partition's file system can "
                "still be intact inside one." % len(big_gaps)
            )
    else:
        if out["container"] in ("vhd", "vhdx", "vmdk", "qcow", "aff"):
            out["notes"].append(
                "The Sleuth Kit did not open this %s container. Inspect it with qemu-img; "
                "conversion to raw or attachment may be required before deriving offsets."
                % out["container"]
            )
        out["partition_table"] = False
        out["sector_size"] = forced or 512
        out["mmls_said"] = (mmls_err.splitlines()[-1] if mmls_err else "mmls returned nothing")
        whole = describe_fs(image, None)
        out["partitions"] = [{
            "slot": "—",
            "description": "the whole image, with no partition table",
            "offset_sectors": 0,
            "offset_bytes": 0,
            "allocated": True,
            "filesystem": whole,
        }]
        out["volumes_readable"] = 1 if whole.get("readable") else 0
        if whole.get("readable"):
            out["notes"].append(
                "No partition table, and the image is a single volume. Run the toolkit with no -o "
                "at all; mmls failing here is the right answer, not a broken image."
            )
        else:
            out["notes"].append(
                "Neither a partition table nor a file system at offset 0. Check the container type "
                "above before anything else, then see filesystem/encrypted."
            )

    ready = [p for p in out["partitions"] if p.get("filesystem", {}).get("readable")]
    out["use"] = [
        {
            "offset_sectors": p["offset_sectors"],
            "fs_type": p["filesystem"].get("fs_type"),
            "example": "fls -r -o %d %s" % (p["offset_sectors"], image)
            if out["partition_table"] else "fls -r %s" % image,
        }
        for p in ready
    ]
    print(json.dumps(out, indent=2))


if __name__ == "__main__":
    main()
