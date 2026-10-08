#!/usr/bin/env python3
"""Identify a file from its bytes, and say when the name disagrees.

A `.jpg` that is a ZIP, a `.txt` with a PE header, a `.pdf` that is an HTML page
with a script in it — these are not edge cases, they are how things are hidden,
and an examiner who trusts the extension walks past them. So this reads the
header and then compares the answer with what the name claimed.

The hash comes back with it, because the first thing a sample needs is an
identity the report can refer to for the rest of the case.

What it identifies with: a table of signatures that carry forensic weight
(executables, archives, registry hives, event logs, prefetch at offset 4 and
its compressed MAM form, shortcuts, AD1 and E01 containers, memory captures) and,
for a file the table does not know, the installed `file` (libmagic) when there
is one. An identification is a reading of the first bytes, not a validation; a
type no source knows is `unrecognised` and its extension is neither a match nor a
mismatch (`extension_matches` is null).

What it covers: a directory is walked in sorted order, a file at a time; every
regular file looked at is in the whole result, whatever `limit` or `mismatch_only`
show inline, and `examined` counts the files actually opened. Symbolic links and
files that are not regular (devices, pipes, sockets) are listed and never opened
or followed. A file that could not be read is an error entry, reported whatever
`mismatch_only` says.
"""
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path

TOOL = {"name": "file_type", "version": 3}
BUDGET_SECONDS = 100          # under the manifest's 120
LIBMAGIC_TIMEOUT = 10
ERRORS_SHOWN = 50
LIMIT_MAX = 5000                # files shown inline; every file looked at is in the whole-result file

class _AdSegments:
    """.ad1, .ad2, ... .ad10 and on: FTK Imager numbers an AD1 image's segments without end."""

    def __contains__(self, ext):
        return len(ext) > 2 and ext[:2] == "ad" and ext[2:].isdigit()

    def __bool__(self):
        return True


AD_SEGMENTS = _AdSegments()


class _EwfSegments:
    """.E01 to .E99 and .EAA on (EnCase), .S01 (SMART) and .Ex01 on (EWF2): every segment opens with the file header."""

    def __init__(self, pattern):
        self.pattern = re.compile(pattern)

    def __contains__(self, ext):
        return bool(self.pattern.fullmatch(ext))

    def __bool__(self):
        return True


EWF1_SEGMENTS = _EwfSegments(r"[es]\d\d|e[a-z]{2}")
EWF2_SEGMENTS = _EwfSegments(r"ex\d\d|ex[a-z]{2}")
EWF_LOGICAL_SEGMENTS = _EwfSegments(r"l\d\d|l[a-z]{2}")
EWF2_LOGICAL_SEGMENTS = _EwfSegments(r"lx\d\d|lx[a-z]{2}")
# What a plain text file is not named: the extensions of formats that are not text. A text file given one of these
# is worth a sentence; a text file named .ps1, .vbs, .js, .reg or .conf is not, and an extension no table lists is no mismatch.
BINARY_EXTENSIONS = {
    "exe", "dll", "sys", "scr", "ocx", "cpl", "efi", "mui", "msi", "zip", "docx", "xlsx", "pptx", "docm", "xlsm", "pptm", "jar", "apk",
    "odt", "ods", "epub", "whl", "ipa", "aff4", "rar", "7z", "gz", "tgz", "bz2", "xz", "doc", "xls", "ppt", "msg", "pdf", "png", "jpg",
    "jpeg", "gif", "wav", "avi", "webp", "sqlite", "sqlite3", "evtx", "lnk", "pf", "ad1", "lime", "dmp", "tar", "hve", "hiv", "class",
    "dylib", "bundle", "so", "elf", "mp3", "mp4", "mov", "iso", "vhd", "vhdx", "vmdk", "qcow2",
}

MAGIC = [
    (0, b"MZ", "PE or DOS executable", {"exe", "dll", "sys", "scr", "ocx", "cpl", "efi", "mui", "msi"}),
    (0, b"\x7fELF", "ELF executable or object", {"so", "o", "elf", "bin", ""}),
    (0, b"\xcf\xfa\xed\xfe", "Mach-O 64-bit", {"dylib", "bundle", "o", ""}),
    (0, b"\xce\xfa\xed\xfe", "Mach-O 32-bit", {"dylib", "bundle", "o", ""}),
    (0, b"PK\x03\x04", "ZIP container", {"zip", "docx", "xlsx", "pptx", "docm", "xlsm", "pptm",
                                          "jar", "apk", "odt", "ods", "epub", "whl", "ipa", "aff4"}),
    (0, b"Rar!\x1a\x07", "RAR archive", {"rar"}),
    (0, b"7z\xbc\xaf\x27\x1c", "7-Zip archive", {"7z"}),
    (0, b"\x1f\x8b", "gzip", {"gz", "tgz", "svg", "log"}),
    (0, b"BZh", "bzip2", {"bz2"}),
    (0, b"\xfd7zXZ\x00", "xz", {"xz"}),
    (0, b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "OLE compound file", {"doc", "xls", "ppt", "msg",
                                                                   "msi", "db", "ms", "automaticdestinations-ms"}),
    (0, b"%PDF-", "PDF", {"pdf"}),
    (0, b"{\\rtf", "RTF", {"rtf", "doc"}),
    (0, b"\x89PNG\r\n\x1a\n", "PNG", {"png"}),
    (0, b"\xff\xd8\xff", "JPEG", {"jpg", "jpeg"}),
    (0, b"GIF8", "GIF", {"gif"}),
    (0, b"RIFF", "RIFF container (wav, avi, webp)", {"wav", "avi", "webp"}),
    (0, b"SQLite format 3\x00", "SQLite database", {"db", "sqlite", "sqlite3", "history",
                                                    "cookies", "places", "dat", ""}),
    (0, b"regf", "Windows registry hive", {"dat", "hve", "hiv", ""}),
    (0, b"ElfFile\x00", "Windows event log", {"evtx"}),
    (0, b"bplist00", "binary property list", {"plist", "btm", "db", ""}),
    (0, b"<?xml", "XML", {"xml", "plist", "svg", "rels", "config"}),
    (0, b"#!", "script with a shebang", {"sh", "py", "pl", "rb", ""}),
    (0, b"\x4c\x00\x00\x00\x01\x14\x02\x00", "Windows shortcut", {"lnk"}),
    (0, b"MAM\x04", "compressed prefetch record", {"pf"}),
    (4, b"SCCA", "prefetch record", {"pf"}),
    (0, b"EVF\x09\x0d\x0a\xff\x00", "EnCase E01 image (EWF, a segment)", EWF1_SEGMENTS),
    (0, b"EVF2\x0d\x0a\x81\x00", "EnCase Ex01 image (EWF2, a segment)", EWF2_SEGMENTS),
    (0, b"LVF\x09\x0d\x0a\xff\x00", "EnCase L01 logical evidence file (EWF, a segment)", EWF_LOGICAL_SEGMENTS),
    (0, b"LVF2\x0d\x0a\x81\x00", "EnCase Lx01 logical evidence file (EWF2, a segment)", EWF2_LOGICAL_SEGMENTS),
    (0, b"EVF\x09", "an EWF header that is not a whole E01 file header", set()),
    (0, b"ADSEGMENTEDFILE\x00", "AccessData AD1 logical image (a segment)", AD_SEGMENTS),
    (0, b"ADCRYPT", "AccessData AD1 logical image, encrypted", {"ad1"}),
    (0, b"AVML", "AVML memory capture", {"lime", "raw", "mem"}),
    (0, b"EMiL", "LiME memory capture", {"lime", "raw", "mem"}),
    (0, b"PAGEDU", "Windows crash dump", {"dmp"}),
    (257, b"ustar", "tar archive", {"tar"}),
]
TEXTY = bytes(range(0x20, 0x7f)) + b"\r\n\t\f\b"


def fail(message, **extra):
    print(json.dumps({"error": message, "tool": TOOL, **extra}))
    raise SystemExit(1)


def class_or_fat(head):
    """0xCAFEBABE opens both a Mach-O universal binary (a big-endian count of architectures) and a
    Java class file (a minor and a major version). The count is small; Java's major starts at 45."""
    count = int.from_bytes(head[4:8], "big")
    major = int.from_bytes(head[6:8], "big")
    if 1 <= count < 45:
        return "Mach-O universal binary", {"dylib", "bundle", ""}
    if 45 <= major <= 90:
        return "Java class file", {"class"}
    return "0xCAFEBABE header (a Mach-O universal binary or a Java class file; neither layout fits)", set()


def identify(head):
    if head[:4] == b"\xca\xfe\xba\xbe" and len(head) >= 8:
        return class_or_fat(head)
    for offset, signature, name, extensions in MAGIC:
        if head[offset:offset + len(signature)] == signature:
            return name, extensions
    sample = head[:512]
    if sample and all(b in TEXTY for b in sample):
        lowered = sample.lstrip().lower()
        if lowered.startswith(b"<!doctype html") or lowered.startswith(b"<html"):
            return "HTML", {"html", "htm"}
        return "text", None                # any extension that is not a binary format's is consistent with text
    return "unrecognised", set()


_libmagic = {"state": None}


def libmagic(path):
    """The installed `file`'s description of a file, or None (and why, in _libmagic)."""
    if _libmagic["state"] is None:
        _libmagic["state"] = shutil.which("file") or False
    if not _libmagic["state"]:
        return None
    try:
        p = subprocess.run([_libmagic["state"], "-b", "--", path], capture_output=True, timeout=LIBMAGIC_TIMEOUT,
                           env=dict(os.environ, LC_ALL="C"))
    except (subprocess.TimeoutExpired, OSError):
        return None
    text = p.stdout.decode("utf-8", "replace").strip()
    return text[:200] if p.returncode == 0 and text else None


def look(path, deadline=None, with_head=False):
    """One entry for one directory entry. Links and non-regular files are named and not opened.
    The hash is of the whole file unless the time budget runs out in it: the entry then says so, with how far it got."""
    try:
        st = os.lstat(path)
    except OSError as exc:
        return {"file": path, "error": exc.strerror or str(exc)}
    claimed = os.path.splitext(path)[1].lstrip(".").lower()
    if stat.S_ISLNK(st.st_mode):
        try:
            target = os.readlink(path)
        except OSError:
            target = None
        return {"file": path, "kind": "symbolic link", "link_target": target, "type": "not opened: a link is listed, never followed",
                "extension": claimed or None, "extension_matches": None}
    if not stat.S_ISREG(st.st_mode):
        return {"file": path, "kind": "not a regular file", "mode": stat.filemode(st.st_mode), "type": "not opened",
                "extension": claimed or None, "extension_matches": None}
    hashed_to = None
    try:
        with open(path, "rb") as fh:
            head = fh.read(4096)
            digest = hashlib.sha256()
            digest.update(head)
            read = len(head)
            while True:
                if deadline is not None and time.monotonic() > deadline:
                    hashed_to = read
                    break
                block = fh.read(1 << 20)
                if not block:
                    break
                read += len(block)
                digest.update(block)
    except OSError as exc:
        return {"file": path, "error": exc.strerror or str(exc)}
    name, extensions = identify(head)
    source = "signature table" if name != "unrecognised" else None
    entry = {"file": path, "bytes": st.st_size, "type": name, "type_source": source}
    if name == "unrecognised":
        described = libmagic(path)
        if described and described != "data":
            entry["type"], entry["type_source"] = described, "libmagic (the installed file command)"
        elif described == "data":
            entry["type_source"] = "none: libmagic calls it data, which is its word for no type"
        else:
            entry["type_source"] = "none: neither the table nor libmagic names it" if _libmagic["state"] else "none: the table does not name it and `file` is not installed"
    # An extension can only be compared with a type whose extensions are known; an unknown type is neither a match nor a mismatch.
    entry["extension"] = claimed or None
    if extensions is None:                       # plain text
        entry["extension_matches"] = claimed not in BINARY_EXTENSIONS
    else:
        entry["extension_matches"] = (claimed in extensions) if extensions else None
    if hashed_to is None:
        entry["sha256"] = digest.hexdigest()
    else:
        entry["sha256"] = None
        entry["hashing"] = "stopped at the time budget after %d of %d bytes: no digest for this file" % (hashed_to, st.st_size)
    if with_head:
        entry["head_hex"] = head[:16].hex()           # opt-in: the first bytes of a key file or a credential store are the secret
    return entry


def walk(path):
    """Every entry under `path`, in sorted order, directories sorted too; a link to a directory is an entry, not a place to go.
    Yields (path, None), or (path, error text) for a directory that could not be listed: that is said, not skipped."""
    if not os.path.isdir(path) or os.path.islink(path):
        yield path, None
        return
    problems = []
    for dirpath, dirs, names in os.walk(path, followlinks=False, onerror=problems.append):
        dirs.sort()
        linked = [d for d in dirs if os.path.islink(os.path.join(dirpath, d))]
        for name in sorted(names + linked):
            yield os.path.join(dirpath, name), None
        dirs[:] = [d for d in dirs if d not in linked]
        while problems:
            exc = problems.pop(0)
            yield os.fsdecode(exc.filename or dirpath), "the directory could not be listed: %s" % (exc.strerror or exc)
    while problems:                          # the last directory walked may be the one that failed
        exc = problems.pop(0)
        yield os.fsdecode(exc.filename or path), "the directory could not be listed: %s" % (exc.strerror or exc)


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


class Results:
    """Every result goes to a file as it is made; the inline page is the filtered, limited view of them."""

    def __init__(self, key):
        digest = hashlib.sha256(json.dumps(key, sort_keys=True).encode()).hexdigest()[:16]
        name = "file_type-%s.jsonl" % digest
        job, out = os.environ.get("JOB_ID"), os.environ.get("OUT")
        if job and out:
            self.path = Path(out) / "tool-output" / name
            self.shown = "store/jobs/%s/out/tool-output/%s" % (re.sub(r"[^A-Za-z0-9_.-]", "_", job), name)
        else:
            agent = re.sub(r"[^A-Za-z0-9_.-]", "_", os.environ.get("AGENT_ID") or "tool")
            self.path = Path("work") / agent / "tool-output" / name
            self.shown = str(self.path)
        self.tmp, self.fh, self.error = None, None, None
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            fd, tmp = tempfile.mkstemp(dir=self.path.parent, prefix=".file_type-")
            self.tmp, self.fh = Path(tmp), os.fdopen(fd, "w", encoding="utf-8")
        except OSError as exc:
            self.error = "the whole result could not be kept (%s: %s)" % (self.path.parent, exc.strerror or exc)

    def add(self, entry):
        if self.fh:
            self.fh.write(json.dumps(entry) + "\n")          # ASCII escapes: a name that is not UTF-8 is written, never lost

    def finish(self, keep):
        """Publish the file when the inline page is not the whole result; drop it when it is."""
        if not self.fh:
            return None
        self.fh.flush()
        os.fsync(self.fh.fileno())
        self.fh.close()
        if keep:
            self.path, self.shown = publish(self.tmp, self.path, self.shown)
            self.tmp = None
            return self.shown
        os.unlink(self.tmp)
        return None


def main():
    try:
        args = json.load(sys.stdin)
    except ValueError as exc:
        fail("arguments are not valid JSON", reason=str(exc))
    if not isinstance(args, dict):
        fail("arguments are a JSON object")
    path = args.get("path")
    if not isinstance(path, str) or not path:
        fail("path is required: a file or a directory to walk")
    if not os.path.lexists(path):
        fail("no such file or directory", path=path)
    limit = args.get("limit", 500)
    if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= LIMIT_MAX:
        fail("limit is a whole number from 1 to %d (every file looked at is kept in a file when the page is not all of them)" % LIMIT_MAX)
    mismatch_only = args.get("mismatch_only", False)
    if not isinstance(mismatch_only, bool):
        fail("mismatch_only is true or false")
    head_hex = args.get("head_hex", False)
    if not isinstance(head_hex, bool):
        fail("head_hex is true or false")

    # A path the caller named that is itself a link (a set held in place under inputs/ is one) is followed once: it is where they
    # asked to look. Links found inside it are listed, never followed.
    root, top = path, None
    if os.path.islink(path):
        real = os.path.realpath(path)
        if not os.path.exists(real):
            fail("the link at path points nowhere", path=path, target=os.readlink(path))
        root, top = real, {"path": path, "target": real}

    def shown(p):
        return path + p[len(root):] if top and (p == root or p.startswith(root.rstrip(os.sep) + os.sep)) else p

    deadline = time.monotonic() + BUDGET_SECONDS
    results = Results([path, mismatch_only, limit, head_hex])
    not_attempted = []
    page, errors = [], []
    counts = {"discovered": 0, "examined": 0, "mismatches": 0, "unrecognised": 0, "links": 0, "not_regular": 0, "errors": 0, "not_attempted": 0, "not_hashed": 0}
    inline_total = 0
    stopped = None
    for target, problem in walk(root):
        counts["discovered"] += 1
        if problem:
            entry = {"file": target, "error": problem}
        elif time.monotonic() > deadline:
            stopped = stopped or "the %d-second time budget was used" % BUDGET_SECONDS
            counts["not_attempted"] += 1
            # Named, not just counted: the entry is in the whole result, and the first ones are in the answer.
            results.add({"file": shown(target), "not_attempted": "the time budget was used before this was looked at"})
            if len(not_attempted) < ERRORS_SHOWN:
                not_attempted.append(shown(target))
            continue
        else:
            entry = look(target, deadline, head_hex)
            if entry.get("hashing"):
                stopped = stopped or "the %d-second time budget was used while hashing %s" % (BUDGET_SECONDS, shown(target))
                counts["not_hashed"] += 1
        entry["file"] = shown(entry["file"])
        results.add(entry)
        if "error" in entry:
            counts["errors"] += 1
            if len(errors) < ERRORS_SHOWN:
                errors.append({"file": entry["file"], "error": entry["error"]})
            continue
        counts["examined"] += entry.get("kind") is None
        counts["links"] += entry.get("kind") == "symbolic link"
        counts["not_regular"] += entry.get("kind") == "not a regular file"
        counts["unrecognised"] += entry.get("type") == "unrecognised" or str(entry.get("type_source", "")).startswith("none")
        mismatch = entry.get("extension_matches") is False
        counts["mismatches"] += mismatch
        if mismatch_only and not mismatch:
            continue
        inline_total += 1
        if len(page) < limit:
            page.append(entry)
    whole = results.finish(keep=inline_total > len(page) or (mismatch_only and counts["discovered"] > inline_total) or counts["errors"] > ERRORS_SHOWN
                           or counts["not_attempted"] > ERRORS_SHOWN)
    why_not_complete = []
    if stopped:
        why_not_complete.append(stopped)
    if counts["errors"]:
        why_not_complete.append("%d entries could not be read or listed (errors)" % counts["errors"])
    if counts["discovered"] and not counts["examined"]:
        why_not_complete.append("nothing was opened: every entry found was a link or not a regular file, and a link is listed, never followed")
    out = {
        "tool": TOOL,
        "path": path,
        "files": page,
        "file_count": len(page),
        "matching_the_filter": inline_total,
        "discovered": counts["discovered"],
        "examined": counts["examined"],
        "not_attempted": counts["not_attempted"],
        "not_attempted_files": not_attempted,
        "not_hashed": counts["not_hashed"],
        "extension_mismatches": counts["mismatches"],
        "unrecognised": counts["unrecognised"],
        "links_listed": counts["links"],
        "not_regular_listed": counts["not_regular"],
        "error_count": counts["errors"],
        "errors": errors,
        "truncated": inline_total > len(page),
        "complete": not why_not_complete,
        "note": "A mismatch is a lead, not a finding: plenty of legitimate files carry an "
                "unexpected extension, and a container type such as ZIP covers a dozen document "
                "formats. What matters is the direction — an executable named .txt is worth a "
                "sentence, a .docx that is a ZIP is simply what a .docx is. A type read from the first "
                "bytes is an identification, not a validation of the file.",
    }
    if whole:
        out["all_results"] = whole
        out["earlier_answers"] = earlier_answers(results.path)
        out["all_results_format"] = "JSON Lines, one complete entry per file looked at, whatever limit and mismatch_only show"
    if results.error:
        out["all_results_error"] = results.error
    if stopped:
        out["stopped"] = stopped
    if why_not_complete:
        out["why_not_complete"] = why_not_complete
    if top:
        out["path_is_a_link"] = {"link": top["path"], "followed_to": top["target"], "note": "the path named is a link, followed once; links inside it are listed, never followed"}
    if counts["not_attempted"] > ERRORS_SHOWN:
        out["not_attempted_note"] = "%d entries were not looked at; the first %d are named, every one is in all_results" % (counts["not_attempted"], ERRORS_SHOWN)
    if counts["errors"] > ERRORS_SHOWN:
        out["errors_note"] = "%d errors; the first %d are listed, the rest are in all_results" % (counts["errors"], ERRORS_SHOWN)
    print(json.dumps(out, indent=2))


if __name__ == "__main__":
    main()
