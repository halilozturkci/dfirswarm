#!/usr/bin/env python3
"""Locate the key material that is already in the evidence, without reading it out.

Almost every container opened in a real case was opened with a key that was
sitting somewhere else in the same case. This sweep finds where, and says what
kind of thing it found. It never says what the thing is.

What it looks for:

    a BitLocker recovery password   48 digits in eight groups of six, in ASCII
                                    text or UTF-16LE text (Windows' own "save a
                                    recovery key" file is UTF-16LE)
    private keys                    the PEM header, with its type
    key files and databases         by name: .bek, id_*, kdbx, key4.db, the
                                    keychains, Login Data, logins.json,
                                    .ppk/.pem/.p12/.pfx, and the names people
                                    save a recovery key under

The 48-digit format carries its own check: each of the eight groups is a
multiple of eleven whose quotient is below 65536 (so no group is above 720885),
which removes almost every coincidental match. `passes_structure_check` says all
eight groups pass. It means a plausible transcription of a recovery password. It
does not mean the value opens any volume. A value with a failing group is still
reported, marked, because a partial transcription is a lead.

THE SECRET-SAFE OUTPUT PATTERN (docs/packs.md, "Secrets and sensitive output").
This tool is its reference implementation; a tool that can reach secret material
copies `SecretValues` below and follows the same four rules.

  1. The answer carries presence, kind, location (file and offset), length and a
     structure result. It carries no value, no characters of one, no masked
     "shape" and no hash, digest or fingerprint of one, however short or salted.
     A finding's `finding_id` is a sequence number and is derived from nothing.
  2. A value is written only when the caller asks (`write_values: true`), only
     when the tool runs as a job (JOB_ID and OUT are set), and only to a file
     under $OUT. The skill that sends the agent here says the job runs with
     `secret_output: true`, which seals every output of the job as sensitive.
     Outside a job the request is refused and nothing is written.
  3. The value file is JSON Lines, mode 0600, created exclusively; each row
     names the same `finding_id`, file and offset as the answer. The answer
     names the file and says `contains_secret_values: true`.
  4. A secret is never on a command line. This tool takes a path and flags only.
  5. A path is printed with any component shaped like the secret withheld (a file or a
     directory named after a recovery password would otherwise print it), in the answer,
     in the files it names and in the digest that names a paging file. The values file
     keeps the real path.

A value is found when it is not glued to more digits: "key_<value>" and "(<value>)" are
found, "<value>7" and "7<value>" are not (a group of seven digits is no group).
"""
import errno
import json
import os
import re
import stat
import sys

# Lossless paging (the same in every library tool that pages): the page an
# agent reads stays small, and when there are more rows the whole result is
# written as JSON Lines under work/<agent>/tool-output (in a job, $OUT/tool-output)
# and named. The file name is a digest of the page's key (a path), never of a value.
import hashlib
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


class SecretValuesRefused(Exception):
    pass


class SecretValues:
    """Where a value goes when, and only when, the caller asked for it.

    The reference implementation of the secret-safe output pattern: copy this
    class unchanged into a tool that has to produce a secret, and call `add`
    once per finding with the finding's id, its locator and the value. With
    `enabled` false it writes nothing and `summary()` says so.
    """

    NAME = "recovery-passwords.jsonl"

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
                "file, not a sealed secret output. Run this as job_run tool=recovery_key_scan with "
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
            "format": "JSON Lines, mode 0600: finding_id, file (the real path), offset, encoding, value" if self.enabled else None,
        }


PARSER = "recovery_key_scan/2"
CHUNK = 4 << 20
# Longer than the longest thing matched (110 bytes of UTF-16LE text), so a match
# across a read boundary is whole in the next window.
OVERLAP = 256
# A match that ends this close to a window's end waits for the next window: the
# UTF-16LE pattern looks two bytes past its end.
MARGIN = 2
DEFAULT_BUDGET = 8 << 20
# Recovery passwords seen are compared with each other to say "the same value as
# F000001" without saying the value; the comparison is held in memory, and capped.
DUPLICATE_CAP = 50000

# Bounded by "not a digit" on each side, as the UTF-16LE pattern is: \b is no boundary between an
# underscore or a letter and a digit, so "key_<value>" would be missed. What is let in that is not a
# value is left to groups_passing_check.
RECOVERY = re.compile(rb"(?<![0-9])(\d{6})-(\d{6})-(\d{6})-(\d{6})-(\d{6})-(\d{6})-(\d{6})-(\d{6})(?![0-9])")
UTF16_GROUP = rb"((?:[0-9]\x00){6})"
RECOVERY_UTF16LE = re.compile(
    rb"(?<![0-9]\x00)" + (rb"-\x00".join([UTF16_GROUP] * 8)) + rb"(?![0-9]\x00)"
)
PEM = re.compile(rb"-----BEGIN ([A-Z ]*PRIVATE KEY)-----")
NAME_HINTS = [
    (re.compile(r"\.bek$", re.I), "BitLocker startup key"),
    (re.compile(r"bitlocker.*recovery|recovery.*key", re.I), "a name people save a recovery key under"),
    (re.compile(r"^id_(rsa|dsa|ecdsa|ed25519)$", re.I), "an SSH private key"),
    (re.compile(r"\.kdbx$", re.I), "a KeePass database"),
    (re.compile(r"^key[34]\.db$", re.I), "the Firefox key database"),
    (re.compile(r"^login\.keychain(-db)?$", re.I), "a macOS keychain"),
    (re.compile(r"^FileVaultMaster\.keychain$", re.I), "a FileVault institutional key"),
    (re.compile(r"^Login Data$", re.I), "Chromium saved passwords"),
    (re.compile(r"^logins\.json$", re.I), "Firefox saved passwords"),
    (re.compile(r"\.(ppk|pem|p12|pfx)$", re.I), "a key or certificate store"),
]
# Directories of a mounted Linux root that hold no evidence. Applied to the
# top of the tree walked only, and every one skipped is reported: a directory
# called dev deeper in the tree is evidence, and is read.
SKIP_TOP_DIRS = {"proc", "sys", "dev"}


def fail(message, **extra):
    print(json.dumps({"error": scrub(message), **extra}))
    raise SystemExit(1)


WITHHELD = "<recovery-password-shaped name withheld>"
PATHS_WITHHELD = [0]
RECOVERY_TEXT = re.compile(RECOVERY.pattern.decode("ascii"))


def shown(path, count=True):
    """A path as it may be printed: any component shaped like a recovery password is withheld.

    The component is tested with the same patterns the scan uses, as ASCII and as
    UTF-16LE text. A file or a directory named after the key would otherwise put the
    key in every row that names it. The values file keeps the real path.
    """
    if not isinstance(path, str):
        return path
    parts = path.split("/")
    for i, part in enumerate(parts):
        if RECOVERY.search(part.encode("utf-8", "replace")) or RECOVERY_UTF16LE.search(part.encode("utf-16-le", "replace")):
            parts[i] = WITHHELD
            if count:
                PATHS_WITHHELD[0] += 1
    return "/".join(parts)


def scrub(text):
    """Text that may quote a path, with anything shaped like a recovery password withheld."""
    return RECOVERY_TEXT.sub(WITHHELD, text)


def valid_group(value):
    """Each group of a BitLocker recovery password is a multiple of 11 whose quotient is below 65536."""
    try:
        number = int(value)
    except ValueError:
        return False
    return number % 11 == 0 and number // 11 < 65536


class FileStats:
    def __init__(self):
        self.bytes_read = 0
        self.error = None


def scan_stream(fh, budget, stats):
    """Yield (kind, start, end, match) for what is in the first `budget` bytes of `fh`.

    The file is read CHUNK bytes at a time and held in a window of the chunk and
    the last OVERLAP bytes of the one before, so memory does not follow the file
    or the budget. A match is yielded once, at its true offset, when the window
    that first holds all of it is scanned. A read error stops the stream after
    the windows already read are scanned; the error is left in `stats.error`.
    """
    carry, base, accepted_through = b"", 0, -1
    try:
        data = fh.read(min(CHUNK, budget))
    except OSError as exc:
        stats.error = exc
        return
    stats.bytes_read += len(data)
    while True:
        nxt = b""
        if data and stats.bytes_read < budget:
            try:
                nxt = fh.read(min(CHUNK, budget - stats.bytes_read))
            except OSError as exc:
                stats.error = exc
            stats.bytes_read += len(nxt)
        final = not nxt
        window = carry + data
        found = []
        for rx, kind in ((RECOVERY, "ascii"), (RECOVERY_UTF16LE, "UTF-16LE"), (PEM, "pem")):
            for m in rx.finditer(window):
                end = base + m.end()
                if end <= accepted_through:
                    continue
                if not final and m.end() > len(window) - MARGIN:
                    continue
                found.append((base + m.start(), kind, m))
        for start, kind, m in sorted(found, key=lambda f: f[0]):
            yield kind, start, m
        if final:
            return
        accepted_through = base + len(window) - MARGIN
        keep = window[-OVERLAP:]
        base += len(window) - len(keep)
        carry, data = keep, nxt


def walk(top, exceptions, counters):
    """Yield the regular files under `top`, in name order, following no link.

    A directory that cannot be listed, a link and a file that is not a regular
    file are reported as exceptions and counted; none is ever dropped quietly.
    """
    stack = [(top, True)]
    while stack:
        directory, is_top = stack.pop()
        try:
            with os.scandir(directory) as it:
                entries = sorted(it, key=lambda e: e.name)
        except OSError as exc:
            counters["directories_failed"] += 1
            exceptions.add({"path": shown(directory), "status": "failed", "what": "directory", "reason": "the directory could not be listed", "error": describe(exc)})
            continue
        subdirs = []
        for entry in entries:
            try:
                if entry.is_symlink():
                    counters["entries_skipped"] += 1
                    exceptions.add({"path": shown(entry.path), "status": "skipped", "reason": "a symbolic link: links are not followed, and the target is read where it lies if it is in the tree"})
                    continue
                if entry.is_dir(follow_symlinks=False):
                    if is_top and entry.name in SKIP_TOP_DIRS:
                        counters["entries_skipped"] += 1
                        exceptions.add({"path": shown(entry.path), "status": "skipped", "reason": "a top-level %s directory of a Linux root: its contents were not scanned; name it as the path to scan it" % entry.name})
                        continue
                    subdirs.append(entry.path)
                    continue
                mode = entry.stat(follow_symlinks=False).st_mode
            except OSError as exc:
                counters["files_attempted"] += 1
                counters["files_failed"] += 1
                exceptions.add({"path": shown(entry.path), "status": "failed", "reason": "the entry could not be examined", "error": describe(exc)})
                continue
            if not stat.S_ISREG(mode):
                counters["entries_skipped"] += 1
                exceptions.add({"path": shown(entry.path), "status": "skipped", "reason": "not a regular file (%s)" % kind_of(mode)})
                continue
            yield entry.path, entry.stat(follow_symlinks=False).st_size
        stack.extend((d, False) for d in reversed(subdirs))


def kind_of(mode):
    for test, name in ((stat.S_ISFIFO, "a named pipe"), (stat.S_ISSOCK, "a socket"), (stat.S_ISBLK, "a block device"),
                       (stat.S_ISCHR, "a character device"), (stat.S_ISDIR, "a directory")):
        if test(mode):
            return name
    return "a special file"


def describe(exc):
    code = errno.errorcode.get(exc.errno, "") if getattr(exc, "errno", None) else ""
    return scrub("%s%s: %s" % (type(exc).__name__, " " + code if code else "", getattr(exc, "strerror", None) or str(exc)))


def optional_bool(args, key):
    value = args.get(key, False)
    if not isinstance(value, bool):
        fail("%s must be true or false" % key)
    return value


def main():
    try:
        args = json.load(sys.stdin)
    except ValueError as exc:
        fail("arguments are not valid JSON", reason=str(exc))
    if not isinstance(args, dict):
        fail("arguments must be a JSON object")
    path = args.get("path")
    if not isinstance(path, str) or not path:
        fail("path is required: a directory to walk or a blob to sweep")
    if not os.path.exists(path):
        fail("no such file or directory", path=shown(path))
    budget = args.get("max_bytes_per_file", DEFAULT_BUDGET)
    if not isinstance(budget, int) or isinstance(budget, bool) or budget < 1024:
        fail("max_bytes_per_file must be an integer of at least 1024")
    limit = args.get("limit", 200)
    if not isinstance(limit, int) or isinstance(limit, bool) or limit < 1:
        fail("limit must be a positive integer")
    write_values = optional_bool(args, "write_values")
    try:
        values = SecretValues(write_values)
    except SecretValuesRefused as exc:
        fail(str(exc), write_values="refused", written=False)

    real = shown(os.path.realpath(path), count=False)
    findings = LosslessPage("recovery_key_scan", [real, "findings"], limit)
    named = LosslessPage("recovery_key_scan", [real, "files worth opening"], limit)
    exceptions = LosslessPage("recovery_key_scan", [real, "files not read, or not read whole"], limit)
    counters = {"files_attempted": 0, "files_read": 0, "files_partial": 0, "files_failed": 0,
                "entries_skipped": 0, "directories_failed": 0}
    totals = {"bytes_read": 0, "bytes_unread_in_partial_files": 0}
    passwords = {"found": 0, "pass_structure_check": 0}
    seen = {}
    capped = False
    serial = 0

    if os.path.isdir(path):
        targets = walk(path, exceptions, counters)
    elif os.path.isfile(path):
        targets = iter([(path, os.stat(path).st_size)])
    else:
        fail("path is neither a directory nor a regular file", path=shown(path))

    try:
        for target, size in targets:
            base = os.path.basename(target)
            for pattern, meaning in NAME_HINTS:
                if pattern.search(base):
                    named.add({"file": shown(target), "bytes": size, "why": meaning})
                    break
            counters["files_attempted"] += 1
            stats = FileStats()
            try:
                fh = open(target, "rb")
            except OSError as exc:
                stats.error = exc
            else:
                # A read error ends the stream and is left in stats.error; what
                # was found before it is kept. An error writing a result is not
                # a read error and is not caught here.
                with fh:
                    for kind, start, m in scan_stream(fh, budget, stats):
                        serial += 1
                        finding_id = "F%06d" % serial
                        if kind == "pem":
                            findings.add({"finding_id": finding_id, "file": shown(target), "offset": start,
                                          "kind": "private key", "key_type": m.group(1).decode("ascii", "replace"),
                                          "parser": PARSER})
                            continue
                        if kind == "ascii":
                            groups = [g.decode() for g in m.groups()]
                        else:
                            groups = [g.replace(b"\x00", b"").decode("ascii") for g in m.groups()]
                        canonical = "-".join(groups)
                        good = sum(1 for g in groups if valid_group(g))
                        row = {"finding_id": finding_id, "file": shown(target), "offset": start,
                               "kind": "BitLocker recovery password",
                               "encoding": "ASCII" if kind == "ascii" else "UTF-16LE",
                               "length": len(canonical), "groups_passing_check": good,
                               "passes_structure_check": good == 8, "parser": PARSER}
                        earlier = seen.get(canonical)
                        if earlier:
                            row["duplicate_of"] = earlier
                        elif len(seen) < DUPLICATE_CAP:
                            seen[canonical] = finding_id
                        else:
                            capped = True
                        passwords["found"] += 1
                        passwords["pass_structure_check"] += 1 if good == 8 else 0
                        findings.add(row)
                        values.add(finding_id, {"file": target, "offset": start, "encoding": row["encoding"],
                                                "passes_structure_check": good == 8}, canonical)
            totals["bytes_read"] += stats.bytes_read
            if stats.error is not None:
                counters["files_failed"] += 1
                exceptions.add({"path": shown(target), "status": "failed", "reason": "the file could not be read whole up to its budget",
                                "error": describe(stats.error), "bytes": size, "bytes_read": stats.bytes_read})
                continue
            counters["files_read"] += 1
            if size > budget:
                counters["files_partial"] += 1
                totals["bytes_unread_in_partial_files"] += size - stats.bytes_read
                exceptions.add({"path": shown(target), "status": "partial", "reason": "read up to max_bytes_per_file; the rest was not read",
                                "bytes": size, "bytes_read": stats.bytes_read, "bytes_unread": size - stats.bytes_read})
    finally:
        values.close()

    pages = {"findings": findings.finish(), "files_worth_opening": named.finish(), "exceptions": exceptions.finish()}
    print(json.dumps({
        "path": shown(path),
        "parser": PARSER,
        "findings": findings.page,
        "finding_count": pages["findings"]["matched"],
        "recovery_passwords": passwords,
        "duplicate_check": "capped: %d distinct values compared, later ones not" % DUPLICATE_CAP if capped else "complete",
        "files_worth_opening": named.page,
        "coverage": {**counters, "max_bytes_per_file": budget, **totals},
        "exceptions": exceptions.page,
        "pages": pages,
        "secret_values": values.summary(),
        "paths_withheld": PATHS_WITHHELD[0],
        **({"paths_note": "A path component shaped like a recovery password is withheld from every path in this answer and in "
                          "the files it names, so a file or directory named after the key does not print it. The real path "
                          "of a finding is in the values file when write_values was asked for; otherwise list the directory."}
           if PATHS_WITHHELD[0] else {}),
        "truncated": any(p["truncated"] for p in pages.values()),
        "note": "Locator output: no recovery value, fragment, masked shape or digest is in this answer or in any file "
                "it names, except the values file when write_values was asked for in a secret_output job. "
                "passes_structure_check means eight groups each divisible by 11 with a quotient below 65536: a "
                "plausible transcription, not proof that it opens any volume. files_read counts files read up to "
                "max_bytes_per_file; exceptions lists every file that failed, was skipped (links, special files, a "
                "top-level proc, sys or dev) or was read only in part, with the bytes not read. A search that found "
                "nothing says nothing about a file listed there. Record in the report WHERE a key came from, because "
                "the report has to say how you got in; hand the value to the operator through the channel they named.",
    }, indent=2))


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except Exception as exc:  # never an empty or clean answer for a failure
        fail("unexpected failure: " + describe(exc) if isinstance(exc, OSError) else "unexpected failure: %s: %s" % (type(exc).__name__, exc))
