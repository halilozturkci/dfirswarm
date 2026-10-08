#!/usr/bin/env python3
"""A broad extraction of a disk image: Plaso's super timeline.

disk-volumes lists every file entry and its MAC times, and reads no file's
contents. This one runs log2timeline over the whole image (every partition
and volume it finds, every parser it carries) into one storage file, then
psort writes it out as a CSV timeline: the searchable form of what the
image's artefacts say happened when. It takes hours on a large image, so its
pack does not run it by itself: the harness offers it as a lead, and a seat
runs it (catalog_request recipe=computer-forensics-base/disk-timeline) or
declines it with why.

    run.py detect --target T [--probe-out DIR]   exit 0 a disk image, 1 not
    run.py run --target T --out DIR

Detect reads signatures only (an EWF, VMDK, VHD(X) or QCOW container, a
partition table, a filesystem's boot sector), so it answers the same on any
host. A run stopped before its end leaves coverage.json saying partial. An --out
that already holds a timeline.plaso or timeline.csv is refused, and said in
coverage.refused.json: the earlier run's coverage.json, which describes the
files that are still there, is left as it was.

Plaso writes its log to the working directory unless told otherwise
(log2timeline-<timestamp>.log.gz, psort-<timestamp>.log.gz), and a job starts
in the run's directory, which is read-only in its worker: on the Belka run
log2timeline and psort both failed there with EROFS on that log. Each is
given its log under --out (--logfile, which Plaso's tools have taken, with
--log_file and --log-file as its aliases, since at least 20180818; the images
install 20260720), and each runs with --out as its working directory, so
nothing either writes lands beside the run.
"""
import argparse
import gzip
import json
import os
import re
import shutil
import struct
import subprocess
import sys
import time

# What `complete` says: the pipeline finished. Plaso's own processing report says what each parser did.
PIPELINE_NOTE = ("complete means log2timeline and psort both exited 0, wrote their files, said no error and no zero event count in what they "
                 "printed, in their logs or in pinfo's report, and the timeline holds an event; it does not say every parser read every "
                 "source or that no record was skipped. pinfo.txt, when it was written, is Plaso's own processing report of the storage "
                 "file: read it before a negative rests on this timeline")
ZONE = re.compile(r"^[A-Za-z0-9_+\-/]{1,64}$")
NOT_COVERED = ("volume shadow copies (run with --vss_stores none); encrypted volumes without their key; unallocated space and "
               "deleted file contents (nothing is carved); formats no parser of the installed Plaso handles, and the text inside documents")


def target_of(value):
    text = open(value, encoding="utf-8").read() if os.path.isfile(value) else value
    target = json.loads(text)
    paths = target.get("paths") or []
    if not paths or not isinstance(paths[0], str):
        raise ValueError("the target names no path")
    return target, paths[0]


def mbr_partitions(head):
    """Whether bytes 446..509 hold at least one partition entry with a type and a size."""
    for i in range(4):
        entry = head[446 + 16 * i: 462 + 16 * i]
        if len(entry) < 16:
            return False
        ptype = entry[4]
        sectors = struct.unpack("<I", entry[12:16])[0]
        if ptype and sectors:
            return True
    return False


def detect(path):
    if not os.path.isfile(path):
        return False, "not a readable file"
    try:
        with open(path, "rb") as fh:
            head = fh.read(65536)
            size = os.path.getsize(path)
            tail = b""
            if size >= 512:
                fh.seek(size - 512)
                tail = fh.read(512)
    except OSError as exc:
        return False, str(exc)
    containers = [
        (0, b"EVF\x09\x0d\x0a\xff\x00", "an EWF image (Plaso reads it through libewf)"),
        (0, b"EVF2\x0d\x0a\x81\x00", "an EWF2 image (Plaso reads it through libewf)"),
        (0, b"KDMV", "a VMDK sparse extent"),
        (0, b"# Disk DescriptorFile", "a VMDK descriptor"),
        (0, b"vhdxfile", "a VHDX disk"),
        (0, b"conectix", "a dynamic VHD disk"),
        (0, b"QFI\xfb", "a QCOW disk"),
        (512, b"EFI PART", "a GPT partition table"),
        (3, b"NTFS    ", "an NTFS volume at sector 0"),
        (3, b"EXFAT   ", "an exFAT volume at sector 0"),
        (54, b"FAT", "a FAT volume at sector 0"),
        (82, b"FAT32", "a FAT32 volume at sector 0"),
        (1080, b"\x53\xef", "an ext volume at sector 0"),
        (1024, b"H+", "an HFS+ volume at sector 0"),
        (1024, b"HX", "an HFSX volume at sector 0"),
        (32, b"NXSB", "an APFS container at sector 0"),
    ]
    for offset, magic, why in containers:
        if head[offset:offset + len(magic)] == magic:
            return True, why
    if tail[:8] == b"conectix":
        return True, "a fixed VHD disk"
    if head[510:512] == b"\x55\xaa" and mbr_partitions(head):
        return True, "an MBR partition table with at least one partition"
    return False, "no disk image, partition table or filesystem signature"


# What Plaso's own words say when a step finished its job and not its work: an error line, a traceback, a worker that was
# killed, a count of events that is zero. Matched in what each step printed, in its log and in pinfo's report; the exit codes
# alone do not say this.
PLASO_ERROR = re.compile(r"\[(?:ERROR|CRITICAL)\]|Traceback \(most recent call last\)|\bworkers?\b.{0,40}\b(?:killed|died|crashed|terminated|not responding)\b", re.I)
PLASO_ZERO = re.compile(r"\bevents?\s+(?:extracted|written|exported|processed)\s*:?\s*0\b", re.I)
SCAN_BYTES = 32 * 1024 * 1024


def plaso_signals(out, names):
    """The lines in these files of `out` that say Plaso failed or found nothing: [(file, kind, count, first line)].
    A file is read to SCAN_BYTES, and a .gz that is not gzip is read as it is."""
    found = []
    for name in names:
        path = os.path.join(out, name)
        if not os.path.isfile(path):
            continue
        counts, first = {"error": 0, "zero events": 0}, {}
        try:
            try:
                with gzip.open(path, "rt", encoding="utf-8", errors="replace") as handle:
                    lines = iter(handle.read(SCAN_BYTES).splitlines())
            except (OSError, EOFError):
                with open(path, "r", encoding="utf-8", errors="replace") as handle:
                    lines = iter(handle.read(SCAN_BYTES).splitlines())
            for line in lines:
                for kind, rx in (("error", PLASO_ERROR), ("zero events", PLASO_ZERO)):
                    if rx.search(line):
                        counts[kind] += 1
                        first.setdefault(kind, line.strip()[:200])
        except OSError:
            continue
        for kind in ("error", "zero events"):
            if counts[kind]:
                found.append((name, kind, counts[kind], first[kind]))
    return found


def program(*names):
    for name in names:
        found = shutil.which(name)
        if found:
            return found
    return None


def write_coverage(out, status, covered, errors, extra=None, name="coverage.json"):
    with open(os.path.join(out, name), "w", encoding="utf-8") as handle:
        json.dump({"recipe": "disk-timeline", "status": status, "covered": covered, "not_covered": NOT_COVERED,
                   "limits_hit": [], "errors": list(errors), "coverage_note": PIPELINE_NOTE, **(extra or {})}, handle, indent=2, sort_keys=True)
        handle.write("\n")


def step(out, name, argv):
    # cwd=out: what a step writes where it stands lands in out, never in the
    # (read-only) directory the job started in.
    with open(os.path.join(out, name + ".stdout"), "wb") as so, open(os.path.join(out, name + ".stderr"), "wb") as se:
        return subprocess.run(argv, stdout=so, stderr=se, cwd=out).returncode


def run(image, out, zone=None):
    out = os.path.abspath(out)
    image = os.path.abspath(image)
    os.makedirs(out, exist_ok=True)
    extra = {"timezone": zone or "not given", "timezone_note": (
        "the zone given to log2timeline for the formats that store local time; psort writes its CSV in UTC" if zone else
        "none given: for the formats that store local time Plaso used its own default, which this recipe does not read back (the "
        "storage file records what it used); pass a timezone in the target (\"timezone\") or RECIPE_TIMEZONE when the machine's zone is known")}
    # A timeline left by an earlier run would be mistaken for this one's.
    stale = [n for n in ("timeline.plaso", "timeline.csv") if os.path.lexists(os.path.join(out, n))]
    if stale:
        # The earlier run's coverage.json describes the files that are still there: it is left as it is, and the
        # refusal is said beside it, so neither record is lost or mistaken for the other.
        write_coverage(out, "failed", "nothing: the output directory already holds %s from an earlier run" % " and ".join(stale),
                       ["%s was already in the output directory; this run will not take it for its own" % " and ".join(stale)], extra,
                       name="coverage.refused.json")
        return 1, "coverage.refused.json"
    began = time.time()
    write_coverage(out, "partial", "started; log2timeline or psort did not finish (stopped before its end)", ["the run ended before Plaso did"], extra)
    l2t = program("log2timeline", "log2timeline.py")
    psort = program("psort", "psort.py")
    if not l2t or not psort:
        missing = [n for n, p in (("log2timeline", l2t), ("psort", psort)) if not p]
        write_coverage(out, "failed", "nothing: Plaso is not in this image", ["%s not on PATH in this job image" % " and ".join(missing)], extra)
        return 1, "coverage.json"
    storage = os.path.join(out, "timeline.plaso")
    collect = [l2t, "--unattended", "--logfile", os.path.join(out, "log2timeline.log.gz"), "--partitions", "all", "--volumes", "all", "--vss_stores", "none"]
    if zone:
        collect += ["--timezone", zone]
    collect += ["--storage-file", storage, image]
    rc = step(out, "log2timeline", collect)
    errors = []
    if rc != 0:
        errors.append("log2timeline exited %d; its output is kept whole in log2timeline.stdout and log2timeline.stderr, its log in log2timeline.log.gz" % rc)

    def fresh(path):
        # written by this run, not left from before it
        return os.path.isfile(path) and os.path.getmtime(path) >= began - 1

    rows = []
    if fresh(storage):
        rows.append(("timeline.plaso", "Plaso storage file of the whole image (psort, pinfo)"))
        prc = step(out, "psort", [psort, "--logfile", os.path.join(out, "psort.log.gz"), "-o", "dynamic", "-w", os.path.join(out, "timeline.csv"), storage])
        if prc != 0:
            errors.append("psort exited %d; its output is kept whole in psort.stdout and psort.stderr, its log in psort.log.gz" % prc)
        if fresh(os.path.join(out, "timeline.csv")):
            rows.append(("timeline.csv", "super timeline (psort -o dynamic): one event per row, every parser's, in time order"))
        pinfo = program("pinfo", "pinfo.py")
        if pinfo:
            # Plaso's processing report of the storage file, kept whole; its text is not parsed here.
            prc = step(out, "pinfo", [pinfo, storage])
            if os.path.isfile(os.path.join(out, "pinfo.stdout")):
                os.replace(os.path.join(out, "pinfo.stdout"), os.path.join(out, "pinfo.txt"))
                rows.append(("pinfo.txt", "Plaso's own processing report of the storage file (pinfo): what its parsers did, warnings included"))
            if prc != 0:
                errors.append("pinfo exited %d; the processing report may be incomplete (pinfo.stderr)" % prc)
    # The programs exited, and said what they did: a worker that was killed or an error line makes it partial, and so does a timeline of no events.
    signals = plaso_signals(out, ["log2timeline.stdout", "log2timeline.stderr", "log2timeline.log.gz", "psort.stdout", "psort.stderr", "psort.log.gz",
                                  "pinfo.txt", "pinfo.stderr"])
    for name, kind, count, first in signals:
        errors.append("%s: %d line(s) say %s, the first: %s" % (name, count, "an error" if kind == "error" else "no events were extracted or written", first))
    csv_path = os.path.join(out, "timeline.csv")
    if fresh(csv_path):
        try:
            with open(csv_path, "rb") as handle:
                data_rows = sum(1 for _ in handle) - 1
            if data_rows < 1:
                errors.append("timeline.csv holds no event (only its header, or nothing): psort wrote a timeline of no events; whether the image holds none "
                              "or a parser failed is not established (read pinfo.txt)")
        except OSError:
            pass
    if signals:
        extra["plaso_signals"] = [{"file": f, "kind": k, "lines": c, "first": first} for f, k, c, first in signals]
    with open(os.path.join(out, "index.tsv"), "w", encoding="utf-8", newline="\n") as handle:
        for rel, what in rows:
            handle.write("%s\t%s\n" % (rel, what))
    names = [r for r, _ in rows if r in ("timeline.plaso", "timeline.csv")]
    if not errors and len(names) == 2:
        write_coverage(out, "complete", "log2timeline over every partition and volume of the image, and psort's timeline of it (the pipeline finished: see coverage_note)", [], extra)
        return 0, "coverage.json"
    if rows:
        write_coverage(out, "partial", "Plaso wrote %s before it ended" % " and ".join(names or ["nothing usable"]), errors, extra)
    else:
        write_coverage(out, "failed", "nothing parsed", errors or ["log2timeline wrote no storage file"], extra)
    return 1, "coverage.json"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("detect", "run"))
    parser.add_argument("--target", required=True)
    parser.add_argument("--out")
    # The census asks every detect step with --probe-out DIR; detect keeps nothing there.
    parser.add_argument("--probe-out")
    args = parser.parse_args()
    try:
        target, image = target_of(args.target)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(json.dumps({"ok": False, "error": str(exc)}))
        return 2
    applies, why = detect(image)
    if args.command == "detect":
        print(json.dumps({"applies": applies, "why": why}))
        return 0 if applies else 1
    if not args.out:
        print(json.dumps({"ok": False, "error": "run needs --out DIR"}))
        return 2
    if not applies:
        print(json.dumps({"ok": False, "status": "unsupported", "why": why}))
        return 2
    zone = target.get("timezone") if isinstance(target, dict) else None
    zone = zone or os.environ.get("RECIPE_TIMEZONE") or None
    if zone is not None and not (isinstance(zone, str) and ZONE.match(zone)):
        print(json.dumps({"ok": False, "error": "timezone is a zone name such as Europe/Istanbul"}))
        return 2
    rc, coverage_file = run(image, args.out, zone)
    status = json.load(open(os.path.join(args.out, coverage_file), encoding="utf-8")).get("status")
    result = {"ok": rc == 0, "status": status}
    if coverage_file != "coverage.json":
        result["coverage"] = coverage_file
    print(json.dumps(result))
    return rc


if __name__ == "__main__":
    sys.exit(main())
