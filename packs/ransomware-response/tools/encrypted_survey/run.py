#!/usr/bin/env python3
"""Survey an extracted tree for files that look like ransomware's work, and say exactly what was and was not looked at.

This is a SURVEY. It names candidates by two heuristics and measures entropy in a few
windows; it does not measure how much of any file was encrypted, whether a file
survives whole, who the family is, or when anything ran. What it does:

  * walks the tree in name order, follows no link, reads no file that is not a regular
    file, and puts every entry it visited, skipped or could not read into a census;
  * names a file a CANDIDATE when its name carries an extension after a known one
    ("report.docx.locked") or when the first 64 KiB of the file reads at 7.5 bits per
    byte or more. A compressed archive reads the same way, so a candidate is a lead;
  * keeps what it could not measure out of the files that matched nothing: a file of
    4096 bytes or less has no entropy measurement (`unmeasured`), a file it could not
    open or read is `read_failed`, and a file not read because the read budget was
    spent is `unmeasured` with that reason. `noncandidate` means only "did not meet
    either heuristic": it is no statement about the file's content;
  * profiles the first `sample` candidates of more than 4096 bytes: entropy of three
    64 KiB windows (head, middle, end) with their offsets and lengths, and the last
    `tail_bytes` bytes. Windows can overlap in a small file, and intermittent
    encryption can fall between them;
  * counts modification times by hour twice, for every regular file and for the
    candidates. The clock is the filesystem's mtime as collected, which an extraction
    or a copy can change; it is not an execution time of anything;
  * reports what the sampled tails share as an observation pending a reference match;
  * withholds the name of a file that is named like a note (ransom_note_scan's pattern) and
    holds an identifier-shaped token, since some families put the victim's identifier there,
    and counts those (`paths_withheld`); other names are printed as they are.

Nothing is cut: the whole census, every candidate and every table longer than `limit`
are written as JSON Lines (under $OUT/tool-output in a job, else work/<agent>/tool-output)
and named in the answer; the census ends with a receipt row, so a file without one is
partial. Exit code 0 means the survey ran; `complete` says whether it covered the tree.
"""
import collections
import datetime
import errno
import hashlib
import json
import math
import os
import re
import stat
import sys
import tempfile
from pathlib import Path

PARSER = "encrypted_survey/2"
WINDOW = 65536
SMALL = 4096                 # a file of at most this many bytes has no entropy measurement
HEAD_THRESHOLD = 7.5         # bits per byte in the head window
END_LOW = 6.5                # bits per byte below which an end window is called low
DEFAULT_SAMPLE, MAX_SAMPLE = 200, 10000
DEFAULT_TAIL, MAX_TAIL = 32, 1024
DEFAULT_BUDGET, MIN_BUDGET = 4 << 30, 4096
DEFAULT_EXCLUDE_TOP = ["proc", "sys", "dev"]
EXT_CAP = 50000              # distinct appended extensions held in memory; the census holds every one
HOUR_CAP = 100000            # distinct hour buckets held in memory per histogram

# Extensions that name what a file was before something was appended to its name. A name that
# keeps one of them and ends in another is a candidate: "report.docx.locked", "report.docx.id[AB12].locked".
KNOWN = {"jpg", "jpeg", "png", "gif", "bmp", "tif", "tiff", "webp", "heic", "heif", "psd",
         "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "rtf", "odt", "ods", "odp", "epub", "msg", "eml",
         "pst", "ost", "txt", "csv", "xml", "json", "html", "md", "log", "ini", "cfg", "conf", "yml", "yaml",
         "zip", "gz", "tgz", "bz2", "xz", "zst", "7z", "rar", "tar", "jar", "apk",
         "mp4", "mp3", "mkv", "avi", "mov", "wmv", "flac", "ogg", "wav", "m4a", "aac",
         "exe", "dll", "sys", "dat", "sql", "bak", "db", "mdb", "accdb",
         "vhd", "vhdx", "vmdk", "iso", "img", "py", "js", "c", "cpp", "h", "java", "php"}
# Formats that are normally compressed or packed: a high-entropy head is what they look like
# whole, so entropy alone is the weakest reason to call one of them a candidate.
COMPRESSED_FORMATS = {"jpg", "jpeg", "png", "gif", "webp", "heic", "heif", "pdf", "docx", "xlsx", "pptx",
                      "odt", "ods", "odp", "epub", "zip", "gz", "tgz", "bz2", "xz", "zst", "7z", "rar", "jar", "apk",
                      "mp4", "mp3", "mkv", "avi", "mov", "wmv", "flac", "ogg", "m4a", "aac"}
# The pattern ransom_note_scan uses to take a file for a note by its name, so that the two tools
# agree on which names are note names.
NAME_HINTS = re.compile(
    r"(readme|read_me|decrypt|restore|recover|unlock|how[\W_]*to|ransom|help[\W_]*|"
    r"your[\W_]*files|instruction|_note|!!!)", re.I)
WITHHELD = "<identifier-shaped name withheld>"
TOKEN = re.compile(r"[A-Za-z0-9]{8,}")
WITHHELD_FILES = set()


# Lossless paging (the same in every library tool that pages): the page an
# agent reads stays small, and when there are more rows the whole result is
# written as JSON Lines under work/<agent>/tool-output (in a job, $OUT/tool-output)
# and named. The file name is a digest of the page's key (a path), never of a value.
# Rows are written with ensure_ascii: a file name that is not UTF-8 reaches Python as lone
# surrogates, which a UTF-8 file cannot hold and a JSON escape can.
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
        self.path, self.shown = output_place(self.tool, key)

    def _write(self, row: object) -> None:
        assert self._out is not None
        self._out.write(json.dumps(row, ensure_ascii=True, default=str))
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


def output_place(tool, key):
    """Where a whole result is written and how the answer names it: (real path, path as cited)."""
    digest = hashlib.sha256(json.dumps(key, sort_keys=True, default=str).encode("utf-8")).hexdigest()[:16]
    name = f"{tool}-{digest}.jsonl"
    job, out = os.environ.get("JOB_ID"), os.environ.get("OUT")
    if job and out:
        # In a job only $OUT is written, and it is sealed as the job's output.
        return Path(out) / "tool-output" / name, "store/jobs/%s/out/tool-output/%s" % (re.sub(r"[^A-Za-z0-9_.-]", "_", job), name)
    agent = re.sub(r"[^A-Za-z0-9_.-]", "_", os.environ.get("AGENT_ID") or "tool")
    path = Path("work") / agent / "tool-output" / name
    return path, str(path)


class Census:
    """One JSON line per visited entry, then a receipt; written whole or not at all.

    The file is made under a temporary name and renamed when the receipt is written, so an
    interrupted survey leaves no file with the census's name: a census that exists is a
    census that ends in its receipt.
    """

    def __init__(self, key):
        self.path, self.shown = output_place("encrypted_survey-census", key)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd, name = tempfile.mkstemp(dir=self.path.parent, prefix=f".{self.path.name}-")
        self._tmp = Path(name)
        self._out = os.fdopen(fd, "w", encoding="utf-8")
        self.rows = 0

    def add(self, row):
        self._out.write(json.dumps(row, ensure_ascii=True, default=str))
        self._out.write("\n")
        self.rows += 1

    def finish(self, receipt):
        receipt = {"record": "receipt", "rows": self.rows, **receipt}
        self._out.write(json.dumps(receipt, ensure_ascii=True, default=str))
        self._out.write("\n")
        self._out.flush()
        os.fsync(self._out.fileno())
        self._out.close()
        os.replace(self._tmp, self.path)


class NoCensus:
    """Stands in for the census when no file can be made for it: the rows are counted, none is kept."""

    shown = None

    def __init__(self):
        self.rows = 0

    def add(self, row):
        self.rows += 1

    def finish(self, receipt):
        pass


def fail(message, **extra):
    print(json.dumps({"error": message, **extra}))
    raise SystemExit(1)


def describe(exc):
    """An error without the path it names: type, errno name and the system's own words."""
    code = errno.errorcode.get(exc.errno, "") if getattr(exc, "errno", None) else ""
    return "%s%s: %s" % (type(exc).__name__, " " + code if code else "", getattr(exc, "strerror", None) or str(exc))


EPOCH = datetime.datetime(1970, 1, 1, tzinfo=datetime.timezone.utc)


def iso_utc(ns):
    """A nanosecond count since 1970-01-01 UTC as ISO 8601 (whole microseconds), or None when
    it is outside what a datetime holds: one file's time is one file's problem. The raw count
    is kept beside it wherever it is shown."""
    try:
        when = EPOCH + datetime.timedelta(microseconds=ns // 1000)
    except (OverflowError, ValueError, TypeError):
        return None
    return when.replace(tzinfo=None).isoformat() + "Z"


def entropy(block):
    """Shannon entropy of the bytes of a block, in bits per byte, to three places."""
    if not block:
        return 0.0
    total = len(block)
    bits = -sum((c / total) * math.log2(c / total) for c in collections.Counter(block).values())
    return round(max(0.0, bits), 3)


def pread_full(fd, length, offset):
    chunks, got = [], 0
    while got < length:
        data = os.pread(fd, length - got, offset + got)
        if not data:
            break
        chunks.append(data)
        got += len(data)
    return b"".join(chunks)


def window_places(size):
    """Head, middle and end: 64 KiB each, the middle centred on half the size, the end flush with it."""
    return [("head", 0), ("middle", max(0, size // 2 - WINDOW // 2)), ("end", max(0, size - WINDOW))]


def overlap(windows):
    spans = sorted((w["offset"], w["offset"] + w["length"]) for w in windows)
    return any(spans[i][1] > spans[i + 1][0] for i in range(len(spans) - 1))


def name_reasons(name):
    """(reasons, appended extension): a known extension followed by another one is the only name rule.

    Whatever sits between the known extension and the last one (an identifier, an address) is part of
    the pattern: "report.docx.id[AB12CD34].locked" matches. A name that loses its extension, or keeps
    its own, does not.
    """
    parts = name.lower().split(".")
    last = parts[-1] if len(parts) > 1 else ""
    if last and last not in KNOWN and any(p in KNOWN for p in parts[1:-1]):
        return ["appended_extension_after_known_extension"], "." + last
    return [], None


def shaped(name):
    """A token of eight or more letters and digits with both kinds present: the shape of many identifiers."""
    for m in TOKEN.finditer(name):
        token = m.group(0)
        if any(c.isdigit() for c in token) and any(c.isalpha() for c in token):
            return True
    return False


def display(path):
    """The path as it may be printed: the name of a file that is named like a note and carries an
    identifier-shaped token is withheld, the same name ransom_note_scan withholds. A file that is not
    named like a note is an encrypted file or an ordinary one, and its name is evidence. Counted once
    per file in WITHHELD_FILES."""
    base = os.path.basename(path)
    if NAME_HINTS.search(base) and shaped(base):
        WITHHELD_FILES.add(path)
        return os.path.join(os.path.dirname(path), WITHHELD)
    return path


def kind_of(mode):
    for test, text in ((stat.S_ISFIFO, "a named pipe"), (stat.S_ISSOCK, "a socket"), (stat.S_ISBLK, "a block device"),
                       (stat.S_ISCHR, "a character device"), (stat.S_ISDIR, "a directory")):
        if test(mode):
            return text
    return "a special file"


def open_regular(path):
    """A descriptor for a regular file, opened without following a link; its fstat comes with it."""
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    fd = os.open(path, flags)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise OSError(errno.EINVAL, "not a regular file (%s)" % kind_of(st.st_mode))
    except OSError:
        os.close(fd)
        raise
    return fd, st


def walk(top, exclude_top, counters, exceptions, skipped, exclusions, census):
    """Yield (path, lstat) for every regular file under `top`, in name order, following no link.

    A directory that cannot be listed, an entry that cannot be examined, a link and a file
    that is not a regular file are each counted, listed and put in the census; none is dropped.
    """
    stack = [(top, True)]
    while stack:
        directory, is_top = stack.pop()
        try:
            with os.scandir(directory) as it:
                entries = sorted(it, key=lambda e: e.name)
        except OSError as exc:
            counters["directories_failed"] += 1
            row = {"path": directory, "status": "failed", "what": "directory", "reason": "the directory could not be listed",
                   "error": describe(exc)}
            exceptions.add(row)
            census.add({"record": "failed_directory", **row})
            continue
        counters["directories_visited"] += 1
        subdirs = []
        for entry in entries:
            try:
                if entry.is_symlink():
                    counters["links_not_followed"] += 1
                    row = {"path": display(entry.path), "status": "skipped", "reason": "a symbolic link: not followed, so neither it nor its target was read"}
                    skipped.add(row)
                    census.add({"record": "skipped", **row})
                    continue
                if entry.is_dir(follow_symlinks=False):
                    if is_top and entry.name in exclude_top:
                        counters["directories_excluded"] += 1
                        row = {"path": entry.path, "reason": "named in exclude_top_level_dirs: a top-level %s directory of a Linux root; "
                                                              "its contents were not read. Name it as the root to read it" % entry.name}
                        exclusions.append(row)
                        census.add({"record": "excluded", **row})
                        continue
                    subdirs.append(entry.path)
                    continue
                st = entry.stat(follow_symlinks=False)
            except OSError as exc:
                counters["entries_failed"] += 1
                row = {"path": display(entry.path), "status": "failed", "reason": "the entry could not be examined", "error": describe(exc)}
                exceptions.add(row)
                census.add({"record": "failed_entry", **row})
                continue
            if not stat.S_ISREG(st.st_mode):
                counters["special_files_skipped"] += 1
                row = {"path": display(entry.path), "status": "skipped", "reason": "not a regular file (%s): not opened" % kind_of(st.st_mode)}
                skipped.add(row)
                census.add({"record": "skipped", **row})
                continue
            yield entry.path, st
        stack.extend((d, False) for d in reversed(subdirs))


class Budget:
    def __init__(self, total):
        self.total = total
        self.read = 0

    def allows(self, n):
        return self.read + n <= self.total

    def spend(self, n):
        self.read += n


def common_suffix(a, b):
    n, i = min(len(a), len(b)), 0
    while i < n and a[-1 - i] == b[-1 - i]:
        i += 1
    return a[len(a) - i:] if i else b""


KNOWN_PARAMS = {"root", "sample", "tail_bytes", "limit", "read_budget_bytes", "exclude_top_level_dirs", "census"}


def int_param(args, key, default, low, high=None, why=""):
    value = args.get(key, default)
    if isinstance(value, bool) or not isinstance(value, int):
        fail("%s must be an integer" % key)
    if value < low:
        fail("%s must be at least %d" % (key, low))
    if high is not None and value > high:
        fail("%s must be at most %d%s" % (key, high, why))
    return value


def hour_bucket(iso):
    return iso[:13] + ":00:00Z"


def bump(counter, key, cap, overflow):
    if key in counter or len(counter) < cap:
        counter[key] += 1
    else:
        overflow[0] += 1


def main():
    try:
        args = json.load(sys.stdin)
    except ValueError as exc:
        fail("arguments are not valid JSON", reason=str(exc))
    if not isinstance(args, dict):
        fail("arguments must be a JSON object")
    root = args.get("root")
    if not isinstance(root, str) or not root:
        fail("root is required: a directory to survey")
    if not os.path.isdir(root):
        fail("no such directory", root=root)
    sample_size = int_param(args, "sample", DEFAULT_SAMPLE, 1, MAX_SAMPLE, " (every profiled candidate is held in the answer's tables)")
    tail_bytes = int_param(args, "tail_bytes", DEFAULT_TAIL, 0, MAX_TAIL)
    limit = int_param(args, "limit", 200, 1)
    budget = Budget(int_param(args, "read_budget_bytes", DEFAULT_BUDGET, MIN_BUDGET))
    full_census = args.get("census", True)
    if not isinstance(full_census, bool):
        fail("census must be true or false")
    exclude_top = args.get("exclude_top_level_dirs", DEFAULT_EXCLUDE_TOP)
    if not isinstance(exclude_top, list) or not all(isinstance(x, str) and x and "/" not in x for x in exclude_top):
        fail("exclude_top_level_dirs must be a list of directory names (no slash); [] excludes nothing")
    unknown = sorted(k for k in args if k not in KNOWN_PARAMS)

    real = os.path.realpath(root)
    census_problem = None
    try:
        census = Census([real, "census"])
    except OSError as exc:
        census, census_problem = NoCensus(), "the census file could not be created (%s): the counts are whole, the per-file rows are not kept" % describe(exc)
    candidates = LosslessPage("encrypted_survey", [real, "candidates"], limit)
    low_tail = LosslessPage("encrypted_survey", [real, "low entropy tail candidates"], limit)
    note_names = LosslessPage("encrypted_survey", [real, "note name candidates"], limit)
    skipped = LosslessPage("encrypted_survey", [real, "entries skipped"], limit)
    exceptions = LosslessPage("encrypted_survey", [real, "directories and entries not read"], limit)
    exclusions = []
    counters = {"directories_visited": 0, "directories_failed": 0, "directories_excluded": 0, "entries_failed": 0,
                "links_not_followed": 0, "special_files_skipped": 0, "regular_files_visited": 0,
                "candidate_files": 0, "noncandidate_files": 0, "unmeasured_files": 0, "read_failed_files": 0,
                "profile_failures": 0, "mtime_unconvertible": 0}
    sizes = {"candidate_bytes": 0, "noncandidate_bytes": 0, "unmeasured_bytes": 0, "read_failed_bytes": 0}
    unmeasured_by_reason = collections.Counter()
    appended = collections.Counter()
    appended_over = [0]
    all_hours, cand_hours = collections.Counter(), collections.Counter()
    all_over, cand_over = [0], [0]
    tails = collections.Counter()
    shared = None
    sampled = 0
    not_profiled = collections.Counter()

    for path, st in walk(root, set(exclude_top), counters, exceptions, skipped, exclusions, census):
        counters["regular_files_visited"] += 1
        size = st.st_size
        modified = iso_utc(st.st_mtime_ns)
        shown_path = display(path)
        row = {"record": "file", "file": shown_path, "bytes": size, "mtime_ns": st.st_mtime_ns, "modified_utc": modified}
        if modified is None:
            counters["mtime_unconvertible"] += 1
            row["mtime_error"] = "the modification time is outside what a datetime holds"
        else:
            bump(all_hours, hour_bucket(modified), HOUR_CAP, all_over)
        base = os.path.basename(path)
        if NAME_HINTS.search(base) and size < 100000:
            note_names.add({"file": shown_path, "bytes": size})
        reasons, ext = name_reasons(base)
        row["appended_extension"] = ext
        head = None
        fd = None
        failure = None
        unmeasured = None
        if size <= SMALL:
            unmeasured = "too_small_for_entropy"
        else:
            need = min(WINDOW, size)
            if not budget.allows(need):
                unmeasured = "read_budget_spent"
            else:
                try:
                    fd, fst = open_regular(path)
                    block = pread_full(fd, need, 0)
                    budget.spend(len(block))
                    head = entropy(block)
                    size = fst.st_size  # what the open file is, if it changed since it was listed
                except OSError as exc:
                    failure = describe(exc)
                    if fd is not None:
                        os.close(fd)
                        fd = None
        row["head_entropy"] = head
        if failure:
            counters["read_failed_files"] += 1
            sizes["read_failed_bytes"] += st.st_size
            row.update({"status": "read_failed", "reason": "the file could not be read", "error": failure})
            if reasons:
                row["name_reasons"] = reasons
            census.add(row)
            continue
        found = list(reasons)
        if head is not None and head >= HEAD_THRESHOLD:
            found.append("head_entropy_at_least_7.5")
            parts = base.lower().rsplit(".", 1)
            if len(parts) == 2 and parts[1] in COMPRESSED_FORMATS and not reasons:
                row["alternative_explanation"] = "its extension (%s) names a format that is normally compressed: high entropy is what it looks like whole" % parts[1]
        if found:
            row["status"] = "candidate"
            row["reasons"] = found
            counters["candidate_files"] += 1
            sizes["candidate_bytes"] += st.st_size
            if ext:
                bump(appended, ext, EXT_CAP, appended_over)
            if modified is not None:
                bump(cand_hours, hour_bucket(modified), HOUR_CAP, cand_over)
            if head is None:
                row["entropy_unmeasured"] = unmeasured
            # Profile: the first `sample` candidates that have a head window, while the budget lasts.
            if head is not None and fd is not None:
                if sampled >= sample_size:
                    row["profiled"] = False
                    row["profile_skipped"] = "sample_limit"
                    not_profiled["sample_limit"] += 1
                else:
                    places = window_places(size)
                    lengths = {name: min(WINDOW, size - at) for name, at in places}
                    need = lengths["middle"] + lengths["end"] + min(tail_bytes, size)
                    if not budget.allows(need):
                        row["profiled"] = False
                        row["profile_skipped"] = "read_budget_spent"
                        not_profiled["read_budget_spent"] += 1
                    else:
                        try:
                            windows = [{"name": "head", "offset": 0, "length": lengths["head"], "entropy": head}]
                            for name, at in places[1:]:
                                block = pread_full(fd, lengths[name], at)
                                budget.spend(len(block))
                                windows.append({"name": name, "offset": at, "length": len(block), "entropy": entropy(block)})
                            tail = b""
                            if tail_bytes:
                                tail = pread_full(fd, min(tail_bytes, size), max(0, size - tail_bytes))
                                budget.spend(len(tail))
                            sampled += 1
                            row["profiled"] = True
                            row["windows"] = windows
                            row["windows_overlap"] = overlap(windows)
                            if tail:
                                row["tail_hex"] = tail.hex()
                                tails[tail.hex()] += 1
                                shared = tail if shared is None else common_suffix(shared, tail)
                            if windows[2]["entropy"] < END_LOW:
                                low_tail.add({"file": shown_path, "bytes": size, "end_entropy": windows[2]["entropy"],
                                              "head_entropy": head, "windows": windows,
                                              "basis": "candidate: the end window reads below 6.5 bits per byte. That can be "
                                                       "padding, zero fill, a trailer or an unencrypted region; it does not show "
                                                       "what was encrypted, and encryption between the windows is not seen"})
                        except OSError as exc:
                            counters["profile_failures"] += 1
                            row["profiled"] = False
                            row["profile_skipped"] = "read_failed"
                            row["profile_error"] = describe(exc)
            elif head is None:
                row["profiled"] = False
                row["profile_skipped"] = unmeasured
                not_profiled[unmeasured] += 1
            candidates.add(row)
            census.add(row)
        elif head is None:
            row["status"] = "unmeasured"
            row["reason"] = unmeasured
            row["reasons"] = []
            counters["unmeasured_files"] += 1
            sizes["unmeasured_bytes"] += st.st_size
            unmeasured_by_reason[unmeasured] += 1
            census.add(row)
        else:
            row["status"] = "noncandidate"
            row["reasons"] = []
            counters["noncandidate_files"] += 1
            sizes["noncandidate_bytes"] += st.st_size
            if full_census:
                census.add(row)
        if fd is not None:
            os.close(fd)

    def hours(counter, key):
        page = LosslessPage("encrypted_survey", [real, key], limit)
        for hour, n in sorted(counter.items(), key=lambda kv: (-kv[1], kv[0])):
            page.add({"hour_utc": hour, "files": n})
        return page

    all_page = hours(all_hours, "all files by hour")
    cand_page = hours(cand_hours, "candidates by hour")
    ext_page = LosslessPage("encrypted_survey", [real, "appended extensions"], limit)
    for ext, n in sorted(appended.items(), key=lambda kv: (-kv[1], kv[0])):
        ext_page.add({"extension": ext, "files": n})
    tail_page = LosslessPage("encrypted_survey", [real, "repeated tails"], limit)
    for tail, n in sorted(tails.items(), key=lambda kv: (-kv[1], kv[0])):
        if n > 1:
            tail_page.add({"tail_hex": tail, "files": n, "basis": "observation"})
    shared_out = None
    if sum(tails.values()) > 1 and shared is not None and len(shared) >= 4:
        shared_out = {"suffix_hex": shared.hex(), "bytes": len(shared), "across_files": sum(tails.values()), "basis": "observation",
                      "pending": "a match against a reference for a family, with the suffix and its position",
                      "caveat": "every sampled tail ends with these bytes. Padding, an ordinary format trailer, duplicated "
                                "content or one tool's output also do; this is not a finding about the family"}

    pages = {"candidates": candidates.finish(), "low_entropy_tail_candidates": low_tail.finish(),
             "note_name_candidates": note_names.finish(), "skipped": skipped.finish(), "exceptions": exceptions.finish(),
             "all_files_mtime_hourly": all_page.finish(), "candidate_mtime_hourly": cand_page.finish(),
             "appended_extension_observations": ext_page.finish(), "repeated_tails": tail_page.finish()}

    c = counters
    reasons = []
    if c["read_failed_files"]:
        reasons.append("%d files could not be read (read_failed)" % c["read_failed_files"])
    if c["profile_failures"]:
        reasons.append("%d candidates could not be profiled: a read failed" % c["profile_failures"])
    if c["directories_failed"] or c["entries_failed"]:
        reasons.append("%d directories could not be listed and %d entries could not be examined" % (c["directories_failed"], c["entries_failed"]))
    if c["directories_excluded"]:
        reasons.append("%d top-level directories were excluded (exclude_top_level_dirs) and not read" % c["directories_excluded"])
    if c["links_not_followed"] or c["special_files_skipped"]:
        reasons.append("%d links were not followed and %d special files were not opened" % (c["links_not_followed"], c["special_files_skipped"]))
    spent = unmeasured_by_reason.get("read_budget_spent", 0) + not_profiled.get("read_budget_spent", 0)
    if spent:
        reasons.append("the read budget (%d bytes) was spent: %d files have no entropy measurement or no profile" % (budget.total, spent))
    if census_problem:
        reasons.append(census_problem)
    complete = "partial" if reasons else "complete"
    receipt = {"parser": PARSER, "complete": complete, "partial_reasons": reasons,
               "coverage": {**counters, "bytes_read": budget.read, "paths_withheld": len(WITHHELD_FILES)}, "bytes": sizes,
               "parameters": {"root": root, "sample": sample_size, "tail_bytes": tail_bytes, "read_budget_bytes": budget.total,
                              "exclude_top_level_dirs": exclude_top, "census": full_census}}
    census.finish(receipt)

    regular = counters["regular_files_visited"]
    print(json.dumps({
        "root": root,
        "parser": PARSER,
        "complete": complete,
        "partial_reasons": reasons,
        "measures": "A survey of candidates. A file is a candidate when its name has an extension after a known one or its first "
                    "64 KiB reads at 7.5 bits per byte or more; a compressed archive reads the same way. It does not measure how "
                    "much of any file was encrypted, whether a file is whole, which family wrote it or when anything ran. "
                    "noncandidate means only that neither heuristic matched.",
        "coverage": {**counters, "unmeasured_by_reason": dict(unmeasured_by_reason), "bytes_read": budget.read,
                     "read_budget_bytes": budget.total},
        "bytes": sizes,
        "candidate_file_fraction": round(counters["candidate_files"] / regular, 4) if regular else None,
        "fraction_basis": "candidate files over regular files visited (unmeasured and unreadable files are in the denominator)",
        "candidates": candidates.page,
        "low_entropy_tail_candidates": low_tail.page,
        "appended_extension_observations": ext_page.page,
        "extension_table": "capped: %d distinct extensions held, %d later files not counted here (the census has every one)" % (EXT_CAP, appended_over[0]) if appended_over[0] else "complete",
        "all_files_mtime_hourly": all_page.page,
        "candidate_mtime_hourly": cand_page.page,
        "clock": "filesystem mtime as collected (the extraction or copy that made this tree can change it), UTC, hourly buckets; "
                 "not an execution time of any program, and not the time any file was encrypted",
        "histogram_tables": {
            name: ("capped: %d distinct hours held, %d files not counted here (the census has every one)" % (HOUR_CAP, over[0]) if over[0] else "complete")
            for name, over in (("all_files", all_over), ("candidates", cand_over))},
        "repeated_tails": tail_page.page,
        "shared_tail_suffix": shared_out,
        "note_name_candidates": note_names.page,
        "exclusions": exclusions,
        "skipped": skipped.page,
        "exceptions": exceptions.page,
        "paths_withheld": len(WITHHELD_FILES),
        **({"paths_note": "The name of a file that is named like a note (the pattern ransom_note_scan uses) and holds a token shaped "
                          "like an identifier (eight or more letters and digits, both kinds) is withheld from every row of this "
                          "answer and of the files it names, once per file counted here: some families put the victim's "
                          "identifier in the note's name. Any other file name, an encrypted file's included, is printed as it is. "
                          "List the directory for a name that was withheld."} if WITHHELD_FILES else {}),
        "sampling": {"method": "first %d profile-eligible candidates in traversal order (directories and names sorted, depth first); "
                               "not random and not stratified; a candidate of 4096 bytes or less has no profile" % sample_size,
                     "sample": sample_size, "profiled": sampled, "candidates_not_profiled": dict(not_profiled),
                     "tail_bytes": tail_bytes, "window_bytes": WINDOW},
        "census": None if census_problem else {"file": census.shown, "rows": census.rows,
                   "scope": "every regular file visited with its status, and every entry skipped, excluded or not read; "
                            "the last line is a receipt" if full_census else
                            "candidates, unmeasured and unreadable files and every entry skipped, excluded or not read; "
                            "files that matched nothing are counted, not listed (census: false)"},
        "pages": pages,
        "truncated": any(p["truncated"] for p in pages.values()),
        **({"unrecognised_parameters": unknown} if unknown else {}),
        "note": "Candidates are leads. Entropy of three windows does not say what part of a file was encrypted, and an "
                "intermittent layout can fall between them; the sampled tails are bytes of the files and say nothing about a "
                "family until a reference matches. Take the questions this cannot answer (extent, recoverability, family, "
                "timing) to file-format validation, a known-good counterpart or a documented layout. coverage and complete say "
                "what was and was not read; a file in read_failed or unmeasured was not shown to be anything.",
    }, indent=2))


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except Exception as exc:  # never an empty or clean answer for a failure
        fail("unexpected failure: %s: %s" % (type(exc).__name__, exc))
