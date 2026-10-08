#!/usr/bin/env python3
"""Drive MemProcFS, which turns a memory image into a file tree, for one call.

MemProcFS is AGPL-3.0, the same licence as this harness, and this pack drives it
as a separate executable. Volatility remains at its own executable boundary
under its Volatility Software License 1.0; the skills invoke `vol` directly.

What the mount gives: sys/proc for the process list, a directory per process
holding its modules, handles, memory map and the regions MemProcFS can read, and
the parsed artefacts it builds. All of it is files, for the length of the call.

This tool starts MemProcFS, does one thing with the tree and stops it, so nothing
is left holding the evidence open. The mount is gone when the call returns: what
survives is the files an export wrote. Three modes:

    list     names, kinds and sizes of a directory (or one file): metadata, no content
    text     one file that is UTF-8 text, written to a file under $OUT/mem_fs
    export   the named virtual files, copied byte for byte to $OUT/mem_fs, with their
             sizes and sha256 in a sealed manifest beside them

THE SECRET-SAFE OUTPUT PATTERN (docs/packs.md, "Secrets and sensitive output"),
copied from recovery_key_scan, the reference implementation, with one change: the
value here is a file. A memory file can hold anything the machine held (a command
line, an environment block, a key, a page of a process), so:

  1. The answer is a locator: virtual path, output file, size, status. It carries
     no content, no characters of it and no digest of it. A digest is in the
     manifest file only.
  2. Content is written only when the caller asks (`write_values: true`), only when
     the tool runs as a job (JOB_ID and OUT are set), and only under $OUT/mem_fs,
     mode 0600, created exclusively. The skill that sends the agent here says the
     job runs with `secret_output: true`, which seals every output of the job as
     sensitive. Outside a job the request is refused before MemProcFS is started.
  3. A secret is never on a command line: this tool takes paths and flags only.

Mounting needs FUSE (a /dev/fuse the process can open, and fusermount3 or fusermount
to unmount), which a sandbox may not allow. When it fails the phase and the reason are
returned, with the engine's own output kept in files, because "no framework was
available" is a legitimate line in a report and "the memory was examined and nothing
was found" is not.
"""
import codecs
import errno
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

PARSER = "mem_fs/3"
CHUNK = 1 << 20
DEFAULT_TIMEOUT = 300
MIN_TIMEOUT = 2
DEFAULT_MAX_BYTES = 4 << 30
MAX_PATHS = 1000
PAGE = 200
CLEANUP_WAIT = 20
OUT_DIR = "mem_fs"
MANIFEST = "export-manifest.jsonl"


# Lossless paging (the same in every library tool that pages): the page an agent
# reads stays small, and when there are more rows the whole result is written as
# JSON Lines under work/<agent>/tool-output (in a job, $OUT/tool-output) and named.
# The file name is a digest of the page's key (a path), never of content.
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
            self._out = None
            result["all_results"] = self.shown
            result["all_results_format"] = "JSON Lines, one complete result per line"
        return result


class SecretValuesRefused(Exception):
    pass


class SecretValues:
    """Where content read from memory goes when, and only when, the caller asked for it.

    The secret-safe output pattern of recovery_key_scan, with a file for a value:
    `open_value` makes the output file, exclusively and private, under
    $OUT/mem_fs; `note` adds one row to the manifest beside them. With `enabled`
    false nothing is written and `summary()` says so.
    """

    def __init__(self, enabled: bool):
        self.enabled = enabled
        self.written = 0
        self._manifest = None
        self.job = os.environ.get("JOB_ID") or ""
        self.out = os.environ.get("OUT") or ""
        if enabled and not (self.job and self.out):
            raise SecretValuesRefused(
                "content is refused outside a job: a file written here would be an ordinary file, not a sealed "
                "secret output, and memory can hold anything the machine held. Run this as job_run tool=mem_fs "
                "with secret_output: true and ask again there; mode list needs no job. Nothing was written and "
                "MemProcFS was not started.")
        self.root = Path(self.out) / OUT_DIR if enabled else None
        job_name = re.sub(r"[^A-Za-z0-9_.-]", "_", self.job)
        self.shown = ("store/jobs/%s/out/%s" % (job_name, OUT_DIR)) if enabled else None

    def shown_path(self, rel: str) -> str:
        return "%s/%s" % (self.shown, rel)

    def open_value(self, rel: str) -> int:
        """A file descriptor for $OUT/mem_fs/<rel>, created exclusively, never through a link, mode 0600."""
        assert self.root is not None
        target = self.root / rel
        target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        parent, root = target.parent.resolve(), self.root.resolve()
        if parent != root and root not in parent.parents:
            raise OSError(errno.EPERM, "the output directory is not inside $OUT/%s" % OUT_DIR)
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        return os.open(str(target), flags, 0o600)

    def note(self, row: dict) -> None:
        assert self.root is not None
        if self._manifest is None:
            self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
            fd = os.open(str(self.root / MANIFEST), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            self._manifest = os.fdopen(fd, "w", encoding="utf-8")
        self._manifest.write(json.dumps(row, ensure_ascii=False) + "\n")
        self._manifest.flush()

    def wrote(self) -> None:
        self.written += 1

    def close(self) -> None:
        if self._manifest is not None:
            self._manifest.flush()
            os.fsync(self._manifest.fileno())
            self._manifest.close()
            self._manifest = None

    def summary(self) -> dict:
        return {
            "requested": self.enabled,
            "written": self.written,
            "values_dir": self.shown if self.written else None,
            "manifest": ("%s/%s" % (self.shown, MANIFEST)) if self.written else None,
            "contains_secret_values": self.written > 0,
            "format": "files byte for byte, mode 0600; the manifest is JSON Lines: item_id, virtual_path, output, bytes, sha256, status" if self.written else None,
        }


def fail(message, **extra):
    print(json.dumps({"error": message, **extra}))
    raise SystemExit(1)


def writable_mount(path):
    """Resolve a mount below this agent's work/<id>/ directory, or, in a job,
    below its $OUT: the one place a worker may write. A pack tool the agent's
    VM cannot run is run again as a job with work/<id>/x given as $OUT/x, and
    a mount refused there was a rerun that could never mount anything. As in
    mem_carve, resolving first (symlinks included) is what holds a path to
    where it really lands."""
    root = Path.cwd().resolve()
    dest = (root / path).resolve() if not Path(path).is_absolute() else Path(path).resolve()
    job_out = Path(os.environ["OUT"]).resolve() if os.environ.get("JOB_ID") and os.environ.get("OUT") else None
    if job_out is not None and job_out in dest.parents:
        return dest
    if dest == root:
        fail("mount must be a child directory, not the run directory itself", mount=str(path))
    if root not in dest.parents:
        fail("mount must stay inside the run directory", mount=str(path))
    work = (root / "work").resolve()
    if dest == work or work not in dest.parents:
        fail("mount must be under your own work/<your id>/ directory", mount=str(path))
    relative = dest.relative_to(work)
    if len(relative.parts) < 2 or relative.parts[0] in ("", ".", ".."):
        fail("mount must name a directory inside work/<your id>/, not work/ itself",
             mount=str(path))
    return dest


class OutsideMount(Exception):
    """A virtual path that is not, or does not resolve to, a place inside the mount."""

    def __init__(self, label, virtual, reason):
        super().__init__("%s %s: %s" % (label, json.dumps(virtual), reason))
        self.label, self.virtual, self.reason = label, virtual, reason


def inside_mount(mount, virtual, label):
    """A virtual path as a path in the mount, held inside it.

    Raises OutsideMount for an empty or absolute path, a `..`, and a link that resolves
    outside the mount; a link loop raises the OSError or RuntimeError of the resolution.
    It never ends the program: it is called from the worker thread, where an exit would
    stop that thread alone and leave the answer to be printed after an error document.
    """
    if not isinstance(virtual, str) or not virtual:
        raise OutsideMount(label, virtual, "must be a non-empty path inside the mount")
    if virtual.startswith("/") or any(part == ".." for part in virtual.split("/")):
        raise OutsideMount(label, virtual, "must stay inside the mount: a relative path with no ..")
    target = (mount / virtual).resolve()
    if target != mount and mount not in target.parents:
        raise OutsideMount(label, virtual, "resolves outside the mount (a link)")
    return target


def output_name(virtual):
    """A virtual path as the relative path its export is written under: each part with anything outside a safe set replaced."""
    parts = [re.sub(r"[^A-Za-z0-9._@+=,-]", "_", p) for p in virtual.split("/") if p not in ("", ".")]
    return "/".join(parts) or "_"


def prerequisites():
    device = "/dev/fuse"
    return {
        "dev_fuse_present": os.path.exists(device),
        "dev_fuse_usable": os.access(device, os.R_OK | os.W_OK),
        "unmount_helper": shutil.which("fusermount3") or shutil.which("fusermount"),
    }


def read_log(path, limit=16384):
    try:
        with open(path, "rb") as fh:
            data = fh.read(limit + 1)
    except OSError:
        return ""
    text = data[:limit].decode("utf-8", "replace")
    return text + ("\n[more in the log file]" if len(data) > limit else "")


def main():
    try:
        args = json.load(sys.stdin)
    except ValueError as exc:
        fail("arguments are not valid JSON", reason=str(exc))
    if not isinstance(args, dict):
        fail("arguments must be a JSON object")
    path = args.get("path")
    if not isinstance(path, str) or not path:
        fail("path is required: the memory image")
    if not os.path.isfile(path):
        fail("no such file", path=path)
    mount_arg = args.get("mount")
    if not isinstance(mount_arg, str) or not mount_arg:
        fail("mount is required: a directory under your own work/<your id>/ to mount the image at "
             "(the rest of work/ is read-only in a VM)")
    mount = writable_mount(mount_arg)
    timeout = args.get("timeout_seconds", DEFAULT_TIMEOUT)
    if not isinstance(timeout, int) or isinstance(timeout, bool) or timeout < MIN_TIMEOUT:
        fail("timeout_seconds must be an integer of at least %d" % MIN_TIMEOUT)
    mode = args.get("mode", "list")
    if mode not in ("list", "text", "export"):
        fail("mode must be list, text or export", mode=mode)
    write_values = args.get("write_values", False)
    if not isinstance(write_values, bool):
        fail("write_values must be true or false")
    limit = args.get("limit", PAGE)
    if not isinstance(limit, int) or isinstance(limit, bool) or limit < 1:
        fail("limit must be a positive integer")
    max_bytes = args.get("max_bytes_per_path", DEFAULT_MAX_BYTES)
    if not isinstance(max_bytes, int) or isinstance(max_bytes, bool) or max_bytes < 1:
        fail("max_bytes_per_path must be a positive integer")

    requested = args.get("list") or ("." if mode == "list" else None)
    paths = args.get("paths")
    if mode == "text":
        if not isinstance(requested, str) or not requested or requested == ".":
            fail("mode text names one file in list: a path inside the mount")
    if mode == "export":
        if not isinstance(paths, list) or not paths or not all(isinstance(p, str) and p for p in paths):
            fail("mode export needs paths: a non-empty list of virtual paths inside the mount")
        if len(paths) > MAX_PATHS:
            fail("at most %d paths in one call; export the rest in another" % MAX_PATHS, paths=len(paths))
    if mode in ("text", "export") and not write_values:
        fail("mode %s writes memory content to a file: ask for it with write_values: true, in a job run with "
             "secret_output: true. Nothing was written and MemProcFS was not started." % mode)
    try:
        secret = SecretValues(mode in ("text", "export") and write_values)
    except SecretValuesRefused as exc:
        fail(str(exc), write_values="refused", written=False)

    binary = shutil.which("memprocfs")
    if not binary:
        fail("memprocfs is not on PATH",
             install="https://github.com/ufrisk/MemProcFS/releases",
             note="MemProcFS is AGPL-3.0, the same licence as this harness. Without it, "
                  "triage/no-framework says what a memory image still gives you, and the report "
                  "should say no framework was available rather than that nothing was found.")
    if mount.exists() and not mount.is_dir():
        fail("mount exists and is not a directory", mount=str(mount))
    # Every path is checked against the mount before MemProcFS is started.
    targets = []
    try:
        if mode == "export":
            for virtual in paths:
                inside_mount(mount, virtual, "paths")
                targets.append(virtual)
        elif requested:
            inside_mount(mount, requested, "list")
    except OutsideMount as exc:
        fail(str(exc), **{exc.label: exc.virtual})
    except (OSError, RuntimeError) as exc:
        fail("a path could not be resolved inside the mount: %s" % exc)
    mount.mkdir(parents=True, exist_ok=True)
    if any(mount.iterdir()):
        fail("mount directory must be empty; refusing stale files or an existing mount",
             mount=str(mount))

    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    stdout_log = mount.parent / ("%s.memprocfs-%s-%d.stdout.log" % (mount.name, stamp, os.getpid()))
    stderr_log = mount.parent / ("%s.memprocfs-%s-%d.stderr.log" % (mount.name, stamp, os.getpid()))
    argv = [binary, "-device", path, "-mount", str(mount)]
    started = time.monotonic()
    deadline = started + timeout
    try:
        stdout_file = open(stdout_log, "xb")
        stderr_file = open(stderr_log, "xb")
    except OSError as exc:
        fail("the engine's log files could not be created next to the mount", reason=str(exc), logs=str(stdout_log))
    try:
        # Files instead of pipes: MemProcFS can be verbose, and a full pipe would
        # otherwise deadlock before the mount becomes readable. They are kept.
        proc = subprocess.Popen(argv, stdout=stdout_file, stderr=stderr_file)
    except OSError as exc:
        stdout_file.close()
        stderr_file.close()
        fail("memprocfs would not start", phase="startup", reason=str(exc), command=" ".join(argv),
             logs={"stdout": str(stdout_log), "stderr": str(stderr_log)})

    state = {"phase": "startup", "abandon": False}
    problem = None  # (phase, message)
    result = {}
    timings = {}
    ready_marker = mount / "sys"
    page = LosslessPage("mem_fs", [str(mount), mode, requested, paths], limit)
    counts = {"requested": len(targets), "exported": 0, "failed": 0, "refused": 0, "not_exported": 0, "partial": 0,
              "not_attempted": 0}

    # --- the work: runs in a thread, so one deadline holds over a read that blocks ---

    def copy_out(source, virtual, item):
        """Copy one virtual file to $OUT/mem_fs/<name>, whole; item['status'] says what happened, and the
        return value is the count it belongs to (exported, failed, refused, not_exported, partial)."""
        rel = output_name(virtual)
        try:
            st = os.lstat(source)
        except FileNotFoundError:
            item["status"] = "failed: not found in the mount"
            return "failed"
        except OSError as exc:
            item["status"] = "failed: %s" % describe(exc)
            return "failed"
        if stat.S_ISDIR(st.st_mode):
            item["status"] = "not exported: a directory (export names files; list shows what a directory holds)"
            return "not_exported"
        if not stat.S_ISREG(st.st_mode):
            item["status"] = "not exported: not a regular file"
            return "not_exported"
        if st.st_size > max_bytes:
            item["status"] = "not exported: %d bytes exceeds max_bytes_per_path (%d); raise it to export this file" % (st.st_size, max_bytes)
            item["bytes"] = st.st_size
            return "not_exported"
        try:
            # Never through a link: the path was resolved just now, and a link planted since
            # is refused by the open rather than followed.
            source_fd = os.open(str(source), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        except OSError as exc:
            item["status"] = "failed: %s could not be opened: %s" % (virtual, describe(exc))
            return "failed"
        try:
            fd = secret.open_value(rel)
        except FileExistsError:
            os.close(source_fd)
            item["status"] = "refused: the output name %s already exists (another virtual path maps to it, or an earlier call wrote it); nothing was overwritten" % rel
            return "refused"
        except OSError as exc:
            os.close(source_fd)
            item["status"] = "failed: the output file could not be created: %s" % describe(exc)
            return "failed"
        digest, size, partial, error = hashlib.sha256(), 0, None, None
        try:
            with os.fdopen(fd, "wb") as out, os.fdopen(source_fd, "rb") as src:
                while True:
                    if state["abandon"]:
                        partial = "the deadline was reached"
                        break
                    chunk = src.read(CHUNK)
                    if not chunk:
                        break
                    if size + len(chunk) > max_bytes:
                        partial = "max_bytes_per_path (%d) was reached while reading" % max_bytes
                        break
                    out.write(chunk)
                    digest.update(chunk)
                    size += len(chunk)
                out.flush()
                os.fsync(out.fileno())
        except OSError as exc:
            error = exc
        item["bytes"] = size
        item["output"] = secret.shown_path(rel)
        if error is not None:
            item["status"] = "failed: reading %s: %s; %d bytes were written and are kept" % (virtual, describe(error), size)
            category = "failed"
        elif partial:
            item["status"] = "partial: %s; %d bytes were written and are kept" % (partial, size)
            category = "partial"
        else:
            item["status"] = "exported"
            category = "exported"
        secret.note({"item_id": item["item_id"], "virtual_path": virtual, "output": rel, "bytes": size,
                     "sha256": digest.hexdigest(), "status": item["status"]})
        secret.wrote()
        return category

    def work_export():
        state["phase"] = "export"
        for number, virtual in enumerate(targets, 1):
            item = {"item_id": "X%06d" % number, "virtual_path": virtual}
            if state["abandon"]:
                item["status"] = "not attempted: the deadline was reached"
                category = "not_attempted"
            else:
                # One item's trouble is that item's status and count, and the next item goes on.
                try:
                    category = copy_out(inside_mount(mount, virtual, "paths"), virtual, item)
                except OutsideMount as exc:
                    item["status"] = "refused: %s" % exc.reason
                    category = "refused"
                except (RuntimeError, OSError) as exc:
                    item["status"] = "failed: %s" % (describe(exc) if isinstance(exc, OSError) else "%s: %s" % (type(exc).__name__, exc))
                    category = "failed"
            counts[category] += 1
            page.add(item)

    def work_text():
        state["phase"] = "read"
        virtual = requested
        source = inside_mount(mount, virtual, "list")
        if not source.is_file():
            raise FileNotFoundError("%s is not a file in the mount" % virtual)
        rel = output_name(virtual)
        fd = secret.open_value(rel)
        decoder = codecs.getincrementaldecoder("utf-8")("strict")
        digest, size, lines, reason = hashlib.sha256(), 0, 0, None
        try:
            with os.fdopen(fd, "wb") as out, open(source, "rb") as src:
                while True:
                    if state["abandon"]:
                        reason = "the deadline was reached"
                        break
                    chunk = src.read(CHUNK)
                    if not chunk:
                        break
                    if b"\x00" in chunk:
                        reason = "a NUL byte at offset %d" % (size + chunk.index(b"\x00"))
                        break
                    try:
                        decoder.decode(chunk)
                    except UnicodeDecodeError as exc:
                        reason = "bytes that are not UTF-8 at offset %d" % (size + exc.start)
                        break
                    out.write(chunk)
                    digest.update(chunk)
                    size += len(chunk)
                    lines += chunk.count(b"\n")
                if reason is None:
                    try:
                        decoder.decode(b"", final=True)
                    except UnicodeDecodeError:
                        reason = "the file ends inside a UTF-8 sequence"
        except BaseException:
            os.unlink(secret.root / rel)
            raise
        if reason:
            os.unlink(secret.root / rel)
            result["not_text"] = "%s is not text: %s. Nothing was written; use mode export for its bytes." % (virtual, reason)
            return
        secret.note({"item_id": "X000001", "virtual_path": virtual, "output": rel, "bytes": size,
                     "sha256": digest.hexdigest(), "status": "exported"})
        secret.wrote()
        counts["exported"] = 1
        result["text"] = {"virtual_path": virtual, "output": secret.shown_path(rel), "encoding": "utf-8",
                          "bytes": size, "lines": lines}

    def describe(exc):
        code = errno.errorcode.get(exc.errno, "") if getattr(exc, "errno", None) else ""
        return "%s%s: %s" % (type(exc).__name__, " " + code if code else "", getattr(exc, "strerror", None) or str(exc))

    def work_list():
        state["phase"] = "read"
        source = inside_mount(mount, requested, "list")
        if not source.exists():
            raise FileNotFoundError("%s is not in the mount" % requested)
        names = sorted(os.listdir(source)) if source.is_dir() else [None]
        for name in names:
            child = source if name is None else source / name
            try:
                st = os.lstat(child)
            except OSError as exc:
                page.add({"name": name or source.name, "error": describe(exc)})
                continue
            row = {"name": name or source.name, "directory": stat.S_ISDIR(st.st_mode)}
            if not row["directory"]:
                row["size"] = st.st_size
            page.add(row)

    def work():
        try:
            {"list": work_list, "text": work_text, "export": work_export}[mode]()
        except BaseException as exc:  # reported by phase, never swallowed
            result["error"] = exc

    try:
        # --- startup: until the mount appears ---
        while True:
            if os.path.ismount(mount) and ready_marker.is_dir():
                break
            if proc.poll() is not None:
                problem = ("startup", "memprocfs exited before the mount appeared (exit status %s)" % proc.returncode)
                break
            if time.monotonic() >= deadline:
                problem = ("startup", "the mount did not appear within %ds" % timeout)
                break
            time.sleep(0.2)
        timings["startup_seconds"] = round(time.monotonic() - started, 2)
        if not problem:
            work_started = time.monotonic()
            worker = threading.Thread(target=work, daemon=True)
            worker.start()
            worker.join(max(0.0, deadline - time.monotonic()))
            if worker.is_alive():
                state["abandon"] = True
                problem = (state["phase"], "the %s phase did not finish within the %ds deadline" % (state["phase"], timeout))
            timings["work_seconds"] = round(time.monotonic() - work_started, 2)
            if "error" in result and not problem:
                exc = result["error"]
                problem = (state["phase"], "%s" % (exc if isinstance(exc, (FileNotFoundError, OutsideMount)) else describe(exc) if isinstance(exc, OSError) else "%s: %s" % (type(exc).__name__, exc)))
    finally:
        cleanup_started = time.monotonic()
        # Stop the engine, then release a FUSE mount: a successful return must not leave
        # a mount holding evidence. A blocked read ends when the engine does.
        proc.terminate()
        try:
            proc.wait(timeout=CLEANUP_WAIT)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=CLEANUP_WAIT)
        if os.path.ismount(mount):
            unmount = shutil.which("fusermount3") or shutil.which("fusermount")
            if unmount:
                subprocess.run([unmount, "-u", str(mount)], stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL, timeout=CLEANUP_WAIT, check=False)
        if os.path.ismount(mount) and not problem:
            problem = ("cleanup", "memprocfs stopped but the FUSE mount remained")
        stdout_file.close()
        stderr_file.close()
        if state["abandon"]:
            worker.join(5)
        secret.close()
        timings["cleanup_seconds"] = round(time.monotonic() - cleanup_started, 2)

    timings["deadline_seconds"] = timeout
    logs = {"stdout": str(stdout_log), "stderr": str(stderr_log),
            "stdout_bytes": stdout_log.stat().st_size, "stderr_bytes": stderr_log.stat().st_size}
    paged = page.finish()
    items = {"items": page.page} if mode == "export" else {}

    if problem:
        phase, message = problem
        fail(message, phase=phase, command=" ".join(argv), mount=str(mount), logs=logs,
             stderr=read_log(stderr_log).strip(), stdout=read_log(stdout_log).strip(),
             prerequisites=prerequisites(), phases=timings,
             counts=counts if mode == "export" else None,
             secret_values=secret.summary(),
             note="Mounting needs FUSE, which a sandbox may refuse. That is a limit on the host, not a finding "
                  "about the evidence, and the report should say so. The engine's own output is in the log files named.",
             **items)
    if "not_text" in result:
        fail(result["not_text"], phase="read", mount=str(mount), logs=logs, secret_values=secret.summary())

    answer = {
        "path": path,
        "parser": PARSER,
        "mode": mode,
        "mount": str(mount),
        "command": " ".join(argv),
        "prerequisites": prerequisites(),
        "phases": timings,
        "logs": logs,
        "secret_values": secret.summary(),
    }
    if mode == "list":
        answer["listed"] = requested
        answer["entries"] = page.page
        answer["entry_count"] = paged["matched"]
    elif mode == "text":
        answer["text"] = result["text"]
        answer["complete"] = True
    else:
        answer["items"] = page.page
        answer["counts"] = counts
        answer["complete"] = counts["exported"] == counts["requested"]
    if paged.get("all_results"):
        answer["complete_results"] = paged["all_results"]
        answer["complete_results_format"] = paged["all_results_format"]
    answer["truncated"] = paged["truncated"]
    answer["note"] = ("The mount is gone now: this tool starts MemProcFS, does one thing with the tree and stops it, so "
                      "nothing is left holding the evidence open. What survives is what was written under "
                      "$OUT/mem_fs (a job's sealed output), and the engine's own output in the log files. "
                      "The answer carries no file content and no digest of one: the manifest named in "
                      "secret_values has each export's size and sha256. A file that was not exported, or only in part, "
                      "is named in items with its status: an export that is not complete says so in complete.")
    print(json.dumps(answer, indent=2))


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except Exception as exc:  # never an empty or clean answer for a failure
        fail("unexpected failure: %s: %s" % (type(exc).__name__, exc))
