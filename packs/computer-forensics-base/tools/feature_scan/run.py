#!/usr/bin/env python3
"""Run bulk_extractor and say what it wrote, instead of leaving a directory.

bulk_extractor reads the bytes and ignores the file system entirely, which is
why it finds an address in a deleted mail store, a URL in a pagefile and a card
number in unallocated space when nothing in the listing points at any of them.
That is also its weakness: it returns everything, and a directory of feature
files with a million lines is not an answer.

So this returns the shape: every file bulk_extractor wrote, what kind it is
(feature file, histogram, run report, alerts, a pcap, other), how many lines each
feature file holds, how many distinct values (a lower bound when there are more
than the cap), and the offset of the first. It returns NO feature value inline: a
feature file holds addresses, card numbers, account names and passwords the
evidence held. The values are in the feature files bulk_extractor wrote, which
are sealed with the job, so run the job with `secret_output: true`. With
`write_values: true`, in a job, the most frequent values of each feature file are
also written to a 0600 file under $OUT, and the answer names it. That file is not the only
place values are: bulk_extractor's own files in out_dir are unfiltered (alerts.txt can hold a whole
recovery key), so out_dir is made 0700 and its files 0600 once the child ends, and the answer says
`out_dir_contains_secret_values` and which kinds hold them.

A feature file is offset, feature, context, tab-separated; the offset is the
whole provenance, there is no path. A histogram file (`*_histogram.txt`, whose lines
are `n=<count>` and a feature) is another schema and is counted apart. The child's
exit code, stdout and stderr are returned and kept in files: a run that exited
nonzero is partial or failed, not clean.
"""
import collections
import errno
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

TOOL = {"name": "feature_scan", "version": 3}
DEFAULT_TIMEOUT = 900
TIMEOUT_MAX = 1000                # the tool's own limit is 1200 seconds: the counting of what bulk_extractor wrote needs the rest
DISTINCT_CAP = 200_000            # distinct values remembered per feature file; past it the count is a lower bound
INVENTORY_SHOWN = 200
# Written by bulk_extractor beside the features; they describe the run, not the evidence.
RUN_FILES = {"report.xml": "run report", "alerts.txt": "alerts the run raised"}
# The scanners bulk_extractor 2.x ships. The ntfs* and win* ones carve records, not
# strings: an $MFT entry, an INDX slack name, a USN record, a prefetch or link file,
# recovered from bytes with no file system around them.
SCANNERS = ["accts", "aes", "base16", "base64", "elf", "email", "evtx", "exif", "facebook",
            "find", "gps", "gzip", "hiberfile", "httplogs", "json", "kml_carved", "msxml",
            "net", "ntfsindx", "ntfslogfile", "ntfsmft", "ntfsusn", "outlook", "pdf", "rar",
            "rtti", "sqlite", "utmp", "vcard_carved", "vin", "windirs", "winlnk", "winpe",
            "winprefetch", "wordlist", "xor", "zip"]
NAME = re.compile(r"^[A-Za-z0-9_]{1,64}$")


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

    NAME = "feature-scan-values.jsonl"

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
                "file, not a sealed secret output. Run this as job_run tool=feature_scan with "
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
            "format": "JSON Lines, mode 0600: finding_id, feature_file, count (occurrences), value (a feature value as bulk_extractor wrote it)" if self.enabled else None,
        }


def fail(message, **extra):
    print(json.dumps({"error": message, "tool": TOOL, **extra}))
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


def lock_down(root):
    """bulk_extractor writes what it found, unfiltered, with the umask's modes: a feature file, a histogram and
    alerts.txt hold the values themselves (addresses, card numbers, a whole recovery key). Once the child has ended the
    directory is the owner's alone (0700) and its files are 0600. Returns what could not be changed."""
    failed = []
    for dirpath, dirs, names in os.walk(root):
        try:
            os.chmod(dirpath, 0o700)
        except OSError as exc:
            failed.append("%s: %s" % (dirpath, exc.strerror or exc))
        for name in names:
            full = os.path.join(dirpath, name)
            if os.path.islink(full):
                continue
            try:
                os.chmod(full, 0o600)
            except OSError as exc:
                failed.append("%s: %s" % (full, exc.strerror or exc))
    return failed


def classify(name, first_line):
    if name in RUN_FILES:
        return "run report" if name == "report.xml" else "alerts"
    if name.endswith(".pcap") or name.endswith(".pcapng"):
        return "pcap"
    if name.endswith(".txt"):
        if name.endswith("_histogram.txt") or (first_line is not None and re.match(r"n=\d+\t", first_line)):
            return "histogram"
        return "features"
    return "other"


def first_content_line(path):
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                if line.strip() and not line.startswith("#"):
                    return line
    except OSError:
        pass
    return None


def summarise(path, cap=DISTINCT_CAP):
    """Feature files are TSV: offset, feature, context. Blank and # lines are headers.
    Returns counts only; the values are tallied to count and rank them and are not returned."""
    counts = collections.Counter()
    lines = uncounted = 0
    first_offset = None
    malformed = 0
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            if not line.strip() or line.startswith("#"):
                continue
            lines += 1
            parts = line.rstrip("\n").split("\t")
            if len(parts) < 2:
                malformed += 1
                continue
            if first_offset is None:
                first_offset = parts[0]
            key = parts[1]
            if key in counts or len(counts) < cap:
                counts[key] += 1
            else:
                uncounted += 1
    return {"lines": lines, "distinct": len(counts), "distinct_capped": uncounted > 0, "occurrences_not_tallied": uncounted,
            "first_offset": first_offset, "malformed_lines": malformed}, counts


def main():
    try:
        args = json.load(sys.stdin)
    except ValueError as exc:
        fail("arguments are not valid JSON", reason=str(exc))
    if not isinstance(args, dict):
        fail("arguments are a JSON object")

    path = args.get("path")
    if not isinstance(path, str) or not path:
        fail("path is required: an image or any blob")
    if not os.path.isfile(path):
        fail("no such file", path=path)

    out_dir = args.get("out_dir")
    if not isinstance(out_dir, str) or not out_dir:
        fail("out_dir is required: a directory under work/ that does not exist yet")
    out_dir = resolve_output(out_dir, "out_dir")
    job_out = os.environ.get("OUT") if os.environ.get("JOB_ID") else None
    if job_out:
        # A job writes in one place, $OUT: a directory elsewhere would fail halfway, or leave bytes outside the sealed output.
        out_root = Path(job_out).resolve()
        if out_root not in (Path.cwd().resolve() / out_dir).resolve().parents:
            fail("in a job out_dir is a directory under $OUT, the one place a job writes", out_dir=out_dir, out=str(out_root))
    if os.path.lexists(out_dir):
        if not os.path.isdir(out_dir):
            fail("out_dir exists and is not a directory", out_dir=out_dir)
        try:
            holds = bool(os.listdir(out_dir))
        except OSError as exc:
            fail("out_dir cannot be listed (%s)" % (exc.strerror or exc), out_dir=out_dir)
        if holds:
            fail("out_dir already holds files; bulk_extractor refuses to write into one", out_dir=out_dir)

    binary = shutil.which("bulk_extractor")
    if not binary:
        fail("bulk_extractor is not on PATH",
             install="brew install bulk_extractor, or apt-get install -y bulk-extractor")

    top = args.get("top", 15)
    if not isinstance(top, int) or isinstance(top, bool) or top < 1:
        fail("top must be a positive integer")
    timeout = args.get("timeout_seconds", DEFAULT_TIMEOUT)
    if not isinstance(timeout, int) or isinstance(timeout, bool) or not 10 <= timeout <= TIMEOUT_MAX:
        fail("timeout_seconds is a whole number from 10 to %d (the tool's own limit is 1200 seconds, and counting what bulk_extractor wrote needs the rest)" % TIMEOUT_MAX)
    write_values = args.get("write_values", False)
    if not isinstance(write_values, bool):
        fail("write_values is true or false")
    try:
        secret = SecretValues(write_values)
    except SecretValuesRefused as exc:
        fail(str(exc), write_values="refused")
    only = args.get("only") or []
    disable = args.get("disable") or []
    for what, names in (("only", only), ("disable", disable)):
        if not isinstance(names, list) or not all(isinstance(n, str) and NAME.match(n) for n in names):
            fail("%s is a list of scanner names (letters, digits and underscores)" % what)

    argv = [binary, "-o", out_dir]
    if len(only) == 1:
        argv += ["-E", only[0]]            # -E is "-x all -E scanner", and only takes one
    elif len(only) > 1:
        argv += ["-x", "all"]
        for name in only:
            argv += ["-e", name]
    for name in disable:
        argv += ["-x", name]
    argv.append(path)

    # The child's words go to files beside out_dir while it runs (bulk_extractor makes out_dir itself and
    # refuses one that has files), and move into it after.
    parent = Path(out_dir).parent
    try:
        parent.mkdir(parents=True, exist_ok=True)
        tmp_out = tempfile.NamedTemporaryFile(dir=parent, prefix=".feature_scan-", suffix=".stdout", delete=False)
        tmp_err = tempfile.NamedTemporaryFile(dir=parent, prefix=".feature_scan-", suffix=".stderr", delete=False)
    except OSError as exc:
        fail("the directory out_dir would be made in cannot be written (%s)" % (exc.strerror or exc), out_dir=out_dir, parent=str(parent))
    timed_out = False
    try:
        proc = subprocess.run(argv, stdout=tmp_out, stderr=tmp_err, timeout=timeout)
        code = proc.returncode
    except subprocess.TimeoutExpired:
        timed_out, code = True, None
    finally:
        tmp_out.close()
        tmp_err.close()

    def read_head(p, n=4000):
        try:
            with open(p, "r", encoding="utf-8", errors="replace") as fh:
                return fh.read(n)
        except OSError:
            return ""

    said = read_head(tmp_err.name, 200000) + read_head(tmp_out.name, 200000)
    if "no such scanner" in said:
        named = [l.strip() for l in said.splitlines() if "no such scanner" in l]
        for p in (tmp_out.name, tmp_err.name):
            os.unlink(p)
        fail("bulk_extractor does not have a scanner by that name", refused=named, scanners=SCANNERS, command=" ".join(argv))
    if not os.path.isdir(out_dir):
        err = read_head(tmp_err.name)
        for p in (tmp_out.name, tmp_err.name):
            os.unlink(p)
        fail("bulk_extractor wrote no output directory", exit_code=code, timed_out=timed_out, stderr=err.strip(), command=" ".join(argv))
    stdout_file, stderr_file = os.path.join(out_dir, "feature_scan.stdout"), os.path.join(out_dir, "feature_scan.stderr")
    os.replace(tmp_out.name, stdout_file)
    os.replace(tmp_err.name, stderr_file)
    locked_failed = lock_down(out_dir)

    files, features, histograms = [], [], []
    counter = 0
    for root_, subdirs, names in os.walk(out_dir):
        subdirs.sort()
        for name in sorted(names):
            full = os.path.join(root_, name)
            rel = os.path.relpath(full, out_dir)
            if os.path.islink(full) or not os.path.isfile(full):
                continue
            size = os.path.getsize(full)
            first = first_content_line(full) if name.endswith(".txt") else None
            kind = classify(name, first)
            entry = {"file": os.path.join(out_dir, rel), "bytes": size, "kind": kind}
            if kind == "features" and size:
                try:
                    stats, counts = summarise(full)
                except OSError as exc:
                    entry["error"] = exc.strerror or str(exc)
                    stats, counts = None, None
                if stats and stats["lines"]:
                    entry.update(stats)
                    entry["feature"] = name[:-4]
                    features.append(entry)
                    if write_values:
                        for value, n in counts.most_common(top):
                            counter += 1
                            secret.add("F%06d" % counter, {"feature_file": entry["file"], "count": n}, value)
            elif kind == "histogram" and size:
                lines = sum(1 for l in open(full, "r", encoding="utf-8", errors="replace") if l.strip() and not l.startswith("#"))
                entry["lines"] = lines
                histograms.append(entry)
            files.append(entry)
    secret.close()
    holding = sorted({f["kind"] for f in files if f.get("bytes") and f["kind"] != "run report" and f["file"] not in (stdout_file, stderr_file)})
    features.sort(key=lambda f: -(f.get("lines") or 0))
    exit_ok = code == 0 and not timed_out
    written = [f for f in files if f["file"] not in (stdout_file, stderr_file)]        # the child's own words are not what it wrote
    status = "complete" if exit_ok else ("partial" if written else "failed")
    result = {
        "tool": TOOL,
        "path": path,
        "out_dir": out_dir,
        "status": status,
        "exit_code": code,
        "timed_out": timed_out,
        "command": " ".join(argv),
        "stdout_file": stdout_file,
        "stderr_file": stderr_file,
        "stderr_head": read_head(stderr_file, 600).strip() or None,
        "scanners_only": only or None,
        "features": features,
        "feature_count": len(features),
        "histograms": histograms,
        "values_inline": False,
        "secret_values": secret.summary(),
        "out_dir_contains_secret_values": bool(holding),
        "kinds_holding_values": holding,
        "out_dir_note": "secret_values is about the values file this tool writes. out_dir holds what bulk_extractor wrote, unfiltered: the kinds listed "
                        "in kinds_holding_values (features, histogram and alerts files among them) carry the values themselves. It is mode 0700 with its "
                        "files 0600; in a job it is sealed with the rest of $OUT, so run the job with secret_output: true.",
        "files": files[:INVENTORY_SHOWN],
        "file_count": len(files),
        "files_written_by_bulk_extractor": len(written),
        "empty_features_omitted": True,
        "note": "No feature value is returned: the feature files hold what the evidence held (addresses, account names, card numbers, "
                "secrets), so read them in a job run with secret_output: true. Each line starts with the byte offset it was found at, and that "
                "offset is the whole provenance: there is no path and no file. A hit is a lead, not a finding, until you have cut the "
                "surrounding bytes and identified what they are. status complete means bulk_extractor exited 0, not that every scanner "
                "reached every byte (report.xml says what ran).",
    }
    if len(files) > INVENTORY_SHOWN:
        result["files_note"] = "the first %d of %d files are listed; the directory holds the rest" % (INVENTORY_SHOWN, len(files))
    if locked_failed:
        result["out_dir_mode_problem"] = "the modes of %d path(s) could not be restricted, so those may be readable by others: %s" % (len(locked_failed), "; ".join(locked_failed[:5]))
    if timed_out:
        result["problem"] = "bulk_extractor did not finish within %d seconds; what it had written is listed and is partial" % timeout
    elif code != 0:
        result["problem"] = "bulk_extractor exited %s; read %s" % (code, stderr_file)
    print(json.dumps(result, indent=2))
    raise SystemExit(0 if status == "complete" else 1)


if __name__ == "__main__":
    main()
