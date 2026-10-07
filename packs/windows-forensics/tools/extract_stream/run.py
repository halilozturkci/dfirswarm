#!/usr/bin/env python3
"""Extract one data stream of an NTFS volume by inode, to a file, with icat.

The stream is written to `output` (a path under the run, never under inputs/), streamed: icat's standard
output goes straight to the file, so a stream of any size is never held in memory and never printed. The
answer is the record a reader cites: the output path, its size and sha256, the image, the offset in sectors,
the inode address as asked and as parsed (entry, attribute type, attribute id), icat's exit status and its
standard error, whole, in a file beside the output. A failed icat leaves what it wrote as `<output>.partial`
and the answer says so; it is never reported as an extraction.

The inode is a Sleuth Kit address: `168` (the default data attribute) or `168-128-4` (entry, attribute type,
attribute id, which names a stream such as an alternate data stream). `offset` is in SECTORS, as icat's -o
is. A file that already exists at `output` is never overwritten, and neither is anything this tool keeps
beside it: a second failed run leaves a second `.partial` and a second `.stderr` under the next free name,
and the answer names the file it kept. `output` is under work/<your id>/ (or work/extracted/<your id>/,
work/quarantine/<your id>/); run as a job, under $OUT, which the harness gives it when the path is written
work/<your id>/...: the run's other directories are read-only there and anywhere else are refused. This is the
same contract as the base pack's icat_extract (a named file, its size and digest), without its image catalogue.
"""
import hashlib
import json
import os
import re
import shutil
import signal
import subprocess
import sys
from pathlib import Path

PARSER = "extract_stream/5"
MAX_TIMEOUT = 270


# BEGIN SHARED PROCESS
# The same text is in esedb_query, extract_stream, sigma_hunt, vss_stores and yara_scan; tests/pack-windows-forensics-process.test.ts
# holds the copies equal. A program a tool runs is started in THIS tool's process group, never in a session of its own: the
# harness ends a tool that runs too long, or is aborted, by killing the tool's group (process.kill(-pid, SIGKILL)), and a
# program in a group of its own goes on writing after the tool is gone. On Linux the kernel is also asked to kill it if the
# tool dies. The tool's own deadline kills the program and what it started by walking the process tree, and SIGTERM, SIGINT
# and SIGHUP do the same and then give the tool a last word.
try:
    import ctypes
except ImportError:  # pragma: no cover
    ctypes = None

STATE = {"last_word": None}    # what to do, with the signal number, when the tool is stopped by a signal
ACTIVE = []                    # the programs running now


def _die_with_parent():  # runs in the child between fork and exec
    try:
        ctypes.CDLL(None).prctl(1, signal.SIGKILL)   # PR_SET_PDEATHSIG
    except Exception:  # noqa: BLE001
        pass


def spawn(argv, **kwargs):
    kwargs.setdefault("stdin", subprocess.DEVNULL)
    if sys.platform.startswith("linux") and ctypes is not None:
        kwargs["preexec_fn"] = _die_with_parent
    return subprocess.Popen(argv, **kwargs)


def descendants(pid):
    """Every process below `pid`, from /proc where there is one, else from ps."""
    kids = {}
    try:
        if os.path.isdir("/proc/self"):
            for entry in os.listdir("/proc"):
                if entry.isdigit():
                    try:
                        with open("/proc/%s/stat" % entry, "rb") as fh:
                            fields = fh.read().rsplit(b")", 1)[1].split()
                        kids.setdefault(int(fields[1]), []).append(int(entry))
                    except (OSError, IndexError, ValueError):
                        continue
        else:
            out = subprocess.run(["ps", "-A", "-o", "pid=,ppid="], capture_output=True, text=True, timeout=10).stdout
            for line in out.splitlines():
                parts = line.split()
                if len(parts) == 2 and parts[0].isdigit() and parts[1].isdigit():
                    kids.setdefault(int(parts[1]), []).append(int(parts[0]))
    except (OSError, subprocess.SubprocessError):
        return []
    found, stack = [], [pid]
    while stack:
        for child in kids.get(stack.pop(), []):
            found.append(child)
            stack.append(child)
    return found


def kill_tree(proc):
    """Kill the program and everything it started. The children are listed first: once the parent is gone they are
    adopted by init and can no longer be found below it."""
    victims = descendants(proc.pid)
    try:
        proc.kill()
    except OSError:
        pass
    for pid in victims:
        try:
            os.kill(pid, signal.SIGKILL)
        except OSError:
            pass


def wait_for(proc, seconds):
    """(exit code, timed out): wait for the program for at most `seconds`; at the deadline it and what it started are killed."""
    ACTIVE.append(proc)
    try:
        try:
            return proc.wait(timeout=seconds), False
        except subprocess.TimeoutExpired:
            kill_tree(proc)
            return proc.wait(), True
    finally:
        if proc in ACTIVE:
            ACTIVE.remove(proc)


def _on_signal(signum, _frame):
    for proc in list(ACTIVE):
        kill_tree(proc)
    last_word = STATE.get("last_word")
    if last_word:
        try:
            last_word(signum)
        except Exception:  # noqa: BLE001 - a last word is best effort
            pass
    os._exit(128 + signum)


def install_signal_handlers():
    for signum in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(signum, _on_signal)
# END SHARED PROCESS
INODE = re.compile(r"^(\d+)(?:-(\d+)(?:-(\d+))?)?$")


def fail(message, **extra):
    print(json.dumps({"error": message, "status": "failed", **extra}))
    raise SystemExit(1)


def own_places():
    """The places this tool may write, resolved, and how to say them. In a job only $OUT is writable (the harness
    maps work/<id>/x to it); anywhere else the agent's own directories under work/ are, and nothing else in the run."""
    job, out = os.environ.get("JOB_ID"), os.environ.get("OUT")
    if job and out:
        return [Path(out).resolve()], "$OUT (run as a job, only $OUT is writable; write the path as work/<your id>/...)"
    agent = re.sub(r"[^A-Za-z0-9_.-]", "_", os.environ.get("AGENT_ID") or "tool")
    root = Path.cwd().resolve()
    places = [root / "work" / agent, root / "work" / "extracted" / agent, root / "work" / "quarantine" / agent]
    return places, "work/%s/, work/extracted/%s/ or work/quarantine/%s/" % (agent, agent, agent)


def resolve_output(out):
    """Where `out` really lands, refusing anything outside the run directory, under inputs/, or outside the places
    the agent may write. A string check is not enough: `work/../inputs/x`, an absolute path and a link that points
    out all name a place that must not be written."""
    root = Path.cwd().resolve()
    dest = (root / out).resolve() if not Path(out).is_absolute() else Path(out).resolve()
    places, said = own_places()
    in_a_job = bool(os.environ.get("JOB_ID") and os.environ.get("OUT"))
    if not in_a_job and (dest == root or root not in dest.parents):
        fail("output must be a file inside the run directory, in %s" % said, output=str(out))
    inputs = root / "inputs"
    if dest == inputs or inputs in dest.parents:
        fail("output cannot be under inputs/", output=str(out))
    if not any(place in dest.parents for place in places):
        fail("output must be a file inside the run directory, in %s" % said, output=str(out))
    return dest


def create_new(base, suffix):
    """Create `base`+`suffix` exclusively (never through a link, never over a file); when that name is taken, the
    next free one: `.2`, `.3`, ... Returns the open descriptor and the path."""
    for n in range(1, 1000):
        path = Path(str(base) + suffix + ("" if n == 1 else ".%d" % n))
        try:
            return os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o644), path
        except FileExistsError:
            continue
    fail("no free name for %s%s after 999 tries" % (base, suffix))


def keep_as(src, base, suffix):
    """Move `src` to `base`+`suffix` without replacing anything: the next free name when it is taken."""
    for n in range(1, 1000):
        path = Path(str(base) + suffix + ("" if n == 1 else ".%d" % n))
        try:
            os.link(src, path)              # fails if the name exists, a dangling link included
            os.unlink(src)
            return path
        except FileExistsError:
            continue
        except OSError:
            if not os.path.lexists(path):   # a file system without hard links
                os.rename(src, path)
                return path
    fail("no free name for %s%s after 999 tries" % (base, suffix))


def main():
    install_signal_handlers()
    try:
        d = json.load(sys.stdin)
    except ValueError as exc:
        fail("arguments are not valid JSON", reason=str(exc))
    if not isinstance(d, dict):
        fail("the arguments must be a JSON object")
    image = d.get("image")
    if not isinstance(image, str) or not image or "\n" in image:
        fail("image must be a single-line path", image=image)
    inode = d.get("inode")
    if isinstance(inode, int) and not isinstance(inode, bool):
        inode = str(inode)
    m = INODE.match(inode) if isinstance(inode, str) else None
    if not m:
        fail("inode must be an address like 168 or 168-128-4 (entry, attribute type, attribute id), or an integer", inode=d.get("inode"))
    offset = d.get("offset", 0)
    if not isinstance(offset, int) or isinstance(offset, bool) or offset < 0:
        fail("offset must be a non-negative sector count", offset=d.get("offset"))
    output = d.get("output")
    if not isinstance(output, str) or not output:
        fail("output is required: the file to write the stream to, under the run directory")
    timeout = d.get("timeout_seconds", 240)
    if isinstance(timeout, bool) or not isinstance(timeout, int) or timeout < 1:
        fail("timeout_seconds must be a positive integer", timeout_seconds=d.get("timeout_seconds"))
    timeout = min(timeout, MAX_TIMEOUT)         # the tool's own limit is 300 s: icat stops before it, and the digest follows
    if not os.path.isfile(image):
        fail("no such image", image=image)
    if shutil.which("icat") is None:
        fail("icat is not on PATH", hint="the Sleuth Kit: brew install sleuthkit, or apt-get install -y sleuthkit")
    dest = resolve_output(output)
    try:
        dest.parent.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        fail("the directory for output could not be created", output=output, reason=str(exc))
    argv = ["icat", "-o", str(offset), image, inode]
    try:
        # Created, never opened over something already there (a link included).
        fd = os.open(str(dest), os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o644)
    except FileExistsError:
        fail("output already exists and is never overwritten", output=output)
    except OSError as exc:
        fail("output could not be created", output=output, reason=str(exc))
    # The standard error goes to a file of its own, new: an earlier run's stays where it is.
    try:
        errfd, stderr_path = create_new(dest, ".stderr")
    except OSError as exc:
        os.close(fd)
        os.unlink(dest)
        fail("the standard error file could not be created", output=output, reason=str(exc))
    def interrupted(signum):
        """The last word of a tool stopped by a signal: what icat wrote is kept as a .partial file and is not an extraction."""
        said = {"error": "stopped by signal %d before icat finished" % signum, "status": "interrupted", "signal": signum,
                "output": output, "stderr_file": os.path.relpath(stderr_path, Path.cwd().resolve())}
        try:
            said["partial_file"] = os.path.relpath(keep_as(dest, dest, ".partial"), Path.cwd().resolve())
            said["note"] = "What icat wrote before it stopped is kept as partial_file; it is not an extraction."
        except (OSError, SystemExit):
            pass
        print(json.dumps(said), flush=True)

    STATE["last_word"] = interrupted
    with os.fdopen(fd, "wb") as out, os.fdopen(errfd, "wb") as err:
        try:
            proc = spawn(argv, stdout=out, stderr=err)
        except OSError as exc:
            fail("icat could not be started: %s" % exc, reason=type(exc).__name__)
        rc, timed_out = wait_for(proc, timeout)
    stderr_bytes = stderr_path.stat().st_size
    if not stderr_bytes:
        stderr_path.unlink()
    shown_stderr = str(os.path.relpath(stderr_path, Path.cwd().resolve())) if stderr_bytes else None
    first_lines = []
    if stderr_bytes:
        with open(stderr_path, "r", encoding="utf-8", errors="replace") as fh:
            first_lines = [l.rstrip("\n") for _, l in zip(range(5), fh)]
    h = hashlib.sha256()
    size = 0
    with open(dest, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
            size += len(chunk)
    answer = {
        "parser": PARSER,
        "image": image,
        "offset_sectors": offset,
        "inode": inode,
        "entry": int(m.group(1)),
        "attribute_type": int(m.group(2)) if m.group(2) is not None else None,
        "attribute_id": int(m.group(3)) if m.group(3) is not None else None,
        "icat_exit_status": rc,
        "timed_out": timed_out,
        "stderr_file": shown_stderr,
        "stderr_bytes": stderr_bytes,
        "stderr_first_lines": first_lines,
    }
    if rc != 0 or timed_out:
        # Kept under a name nothing has: a second failed run never replaces what the first kept.
        partial = keep_as(dest, dest, ".partial")
        answer.update({"status": "failed", "error": "icat failed" if not timed_out else "icat did not finish in time",
                       "partial_file": os.path.relpath(partial, Path.cwd().resolve()), "partial_bytes": size,
                       "note": "What icat wrote before it stopped is kept as partial_file; it is not an extraction."})
        print(json.dumps(answer, indent=2))
        raise SystemExit(1)
    answer.update({"status": "complete", "output": output, "size": size, "sha256": h.hexdigest()})
    print(json.dumps(answer, indent=2))


if __name__ == "__main__":
    try:
        main()
    except OSError as exc:
        fail("a file operation failed: %s" % exc, reason=type(exc).__name__)
