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
# and SIGHUP do the same and then give the tool a last word. Only what is
# below a program this tool started and has not yet waited for is ever signalled: the walk starts at that program's pid
# and nowhere else, and a program that has been waited for (its pid may be another process's by now) is left alone. The
# walk has no bound but the number of processes. Two cases leave the tree running: a ps that needs more than PS_WAIT
# seconds, and a sandbox that denies both libproc and ps (macOS). A stop signal is the one case that reaches further: it also
# ends everything below the tool itself (a program that was forked a moment before it was entered in ACTIVE is among it) and what
# the tool started and lost (reap_orphans): a process that was seen below the tool, in the tool's own group, and whose parent has since
# ended. Nothing else is ever ended: a process the tool never saw in its tree (the next stage of a pipeline the tool heads, a process a
# launcher put in the group) is left alone, whoever leads the group. A program that has ended while something it started still
# holds its pipes does not hold the tool: communicate_bounded gives the pipes PIPE_GRACE seconds and goes on without them. (In the
# windows lineage only the windows-artefacts recipe and lnk_jumplist call it; the lineage is one text, so the others carry it unused.)
import time

try:
    import ctypes
except ImportError:  # pragma: no cover
    ctypes = None

STATE = {"last_word": None}    # what to do, with the signal number, when the tool is stopped by a signal
ACTIVE = []                    # the programs running now
SEEN = set()                   # the pids seen below a program this tool started: the only ones reap_orphans may end once their parent is gone


def _die_with_parent():  # runs in the child between fork and exec
    try:
        ctypes.CDLL(None).prctl(1, signal.SIGKILL)   # PR_SET_PDEATHSIG
    except Exception:  # noqa: BLE001
        pass


def spawn(argv, **kwargs):
    kwargs.setdefault("stdin", subprocess.DEVNULL)
    if sys.platform.startswith("linux") and ctypes is not None:
        kwargs["preexec_fn"] = _die_with_parent
    proc = subprocess.Popen(argv, **kwargs)
    SEEN.add(proc.pid)
    return proc


def _children_libproc(pid):
    """The direct children of `pid` on macOS, from libproc (macOS only: proc_listchildpids is not a symbol of the other
    BSDs; a library call, so no program is started and nothing can be slow); None when the library, the symbol or the
    call is not there."""
    try:
        import ctypes.util
        lib = ctypes.CDLL(ctypes.util.find_library("proc") or "/usr/lib/libproc.dylib", use_errno=True)
        lib.proc_listchildpids.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_int]
        lib.proc_listchildpids.restype = ctypes.c_int
        size = 256
        while size <= 1 << 16:
            buf = (ctypes.c_int * size)()
            if lib.proc_listchildpids(pid, buf, ctypes.sizeof(buf)) < 0:
                return None
            found = []
            for value in buf:
                if value <= 0:
                    break
                found.append(int(value))
            if len(found) < size:
                return found
            size *= 4
        return found
    except Exception:  # noqa: BLE001 - no library, no symbol: the caller falls back
        return None


PS_WAIT = 10    # seconds the ps fallback is given: ps is slow on a heavily loaded host, and a tree that is not found is a program left running


def _below(kids, pid):
    found, seen, stack = [], {pid}, [pid]
    while stack:
        for child in kids.get(stack.pop(), []):
            if child not in seen:
                seen.add(child)
                found.append(child)
                stack.append(child)
    return found


def _libproc_works(pid):
    """Whether an empty libproc answer for `pid` can be believed: libproc has just listed `pid` as this tool's own child, or, when `pid`
    is the tool itself, has just listed the tool as its parent's child. A library that lists nothing for a live process is not working
    (as in a sandbox that denies it)."""
    if pid in (_children_libproc(os.getpid()) or []):
        return True
    return pid == os.getpid() and os.getpid() in (_children_libproc(os.getppid()) or [])


def descendants(pid):
    """Every process below `pid` (never one beside it): from /proc where there is one, else from libproc, else from ps
    (given PS_WAIT seconds). libproc is believed when it lists a child; an empty answer is believed only when libproc has
    just listed this tool's own child `pid` (a library that answers nothing for a live child is not working, as in a
    sandbox that denies it), and otherwise ps is asked."""
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
            first = _children_libproc(pid)
            if first:
                found, seen, stack = list(first), {pid, *first}, list(first)
                while stack:
                    for child in _children_libproc(stack.pop()) or []:
                        if child not in seen:
                            seen.add(child)
                            found.append(child)
                            stack.append(child)
                return found
            if first is not None and _libproc_works(pid):
                return []
            out = subprocess.run(["ps", "-A", "-o", "pid=,ppid="], capture_output=True, text=True, timeout=PS_WAIT).stdout
            for line in out.splitlines():
                parts = line.split()
                if len(parts) == 2 and parts[0].isdigit() and parts[1].isdigit():
                    kids.setdefault(int(parts[1]), []).append(int(parts[0]))
    except (OSError, subprocess.SubprocessError):
        return []
    return _below(kids, pid)


def _process_table():
    """{pid: (parent pid, process group)} for every process, from /proc where there is one, else from ps (given PS_WAIT seconds);
    None when neither answers."""
    table = {}
    try:
        if os.path.isdir("/proc/self"):
            for entry in os.listdir("/proc"):
                if entry.isdigit():
                    try:
                        with open("/proc/%s/stat" % entry, "rb") as fh:
                            fields = fh.read().rsplit(b")", 1)[1].split()
                        table[int(entry)] = (int(fields[1]), int(fields[2]))
                    except (OSError, IndexError, ValueError):
                        continue
        else:
            out = subprocess.run(["ps", "-A", "-o", "pid=,ppid=,pgid="], capture_output=True, text=True, timeout=PS_WAIT).stdout
            for line in out.splitlines():
                parts = line.split()
                if len(parts) == 3 and all(part.isdigit() for part in parts):
                    table[int(parts[0])] = (int(parts[1]), int(parts[2]))
    except (OSError, subprocess.SubprocessError):
        return None
    return table


def _sample(pid):
    """Remember what is below `pid` now, by the cheap routes only (/proc, or libproc on macOS; never a program): a process that is seen
    here and later loses its parent is the tool's to end, and one that was never seen is not."""
    try:
        if os.path.isdir("/proc/self"):
            kids = {}
            for child, (parent, _group) in (_process_table() or {}).items():
                kids.setdefault(parent, []).append(child)
            SEEN.update(_below(kids, pid))
        else:
            seen, stack = {pid}, [pid]
            while stack:
                for child in _children_libproc(stack.pop()) or []:
                    if child not in seen:
                        seen.add(child)
                        stack.append(child)
            SEEN.update(seen - {pid})
    except Exception:  # noqa: BLE001 - a sample is best effort
        pass


def _pipe_inodes(proc):
    """The inodes of the pipes the tool holds with `proc` (Linux: /proc names a pipe by it; elsewhere the answer is not used)."""
    found = set()
    for handle in (proc.stdin, proc.stdout, proc.stderr):
        try:
            if handle is not None:
                found.add(os.fstat(handle.fileno()).st_ino)
        except (OSError, ValueError):
            pass
    return found


def _holds_pipe(pid, inodes):
    """Whether `pid` holds one of the pipes (Linux only, from /proc/<pid>/fd): the pipes are private to the tool and what it started."""
    try:
        for name in os.listdir("/proc/%d/fd" % pid):
            try:
                link = os.readlink("/proc/%d/fd/%s" % (pid, name))
            except OSError:
                continue
            if link.startswith("pipe:[") and link.endswith("]") and int(link[6:-1]) in inodes:
                return True
    except (OSError, ValueError):
        pass
    return False


def reap_orphans(inodes=None):
    """Kill what this tool started and lost: a process of the tool's own group that is no longer below the tool (its parent ended and
    init adopted it, so the walk from a program's pid cannot find it) and that the tool knows to be its own: it was seen below the tool
    (SEEN: the programs it started, the trees it listed, the samples taken while it waited), or, on Linux, it holds one of `inodes`,
    the pipes the tool made. A process the tool never saw in its tree is not touched, whoever leads the group: the next stage of a
    pipeline the tool heads, or a process a launcher put in the group, is not the tool's. A process outside the group is never looked
    at, and a pid is checked against the group again at the moment it is signalled. Returns the pids signalled."""
    me = os.getpid()
    try:
        if os.getpgrp() != me:
            return []
    except OSError:
        return []
    table = _process_table()
    if not table:
        return []
    kids = {}
    for pid, (parent, _group) in table.items():
        kids.setdefault(parent, []).append(pid)
    below = set(_below(kids, me))
    on_linux = os.path.isdir("/proc/self")
    killed = []
    for pid, (_parent, group) in table.items():
        if group != me or pid == me or pid in below:
            continue
        if pid not in SEEN and not (inodes and on_linux and _holds_pipe(pid, inodes)):
            continue
        try:
            if os.getpgid(pid) != me:
                continue
            os.kill(pid, signal.SIGKILL)
            killed.append(pid)
        except OSError:
            pass
    return killed


def kill_tree(proc):
    """Kill the program and everything it started. The children are listed first: once the parent is gone they are
    adopted by init and can no longer be found below it. A program already waited for is not touched: its pid is free to
    be another process's, and the walk below it would be that process's children."""
    if proc.poll() is not None:
        return
    try:
        proc.send_signal(signal.SIGSTOP)    # a program that is stopped forks nothing more while its tree is listed
    except OSError:
        pass
    try:
        victims = descendants(proc.pid)
        SEEN.update(victims)
    finally:
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


PIPE_GRACE = 1.0    # seconds the pipes of a program that has ended are given to reach end of file


def communicate_bounded(proc, seconds, input=None):
    """(stdout bytes, stderr bytes, timed out) for a program started with pipes, in bytes. At `seconds` the program and what it started
    are killed (timed out). A program that has ended while something it started still holds its pipes (a daemon, a helper that
    inherited them) does not hold the tool: the pipes are given PIPE_GRACE seconds, what the program wrote is kept, what the tool
    lost is killed (reap_orphans), and the pipes are let go. The pipes are read here and by nothing else, so letting them go is safe."""
    deadline = time.monotonic() + max(0.1, seconds)
    out = err = b""
    started, timed_out = False, False
    while proc.poll() is None:
        now = time.monotonic()
        if now >= deadline:
            timed_out = True
            kill_tree(proc)
            break
        _sample(proc.pid)
        try:
            out, err = proc.communicate(None if started else input, timeout=max(0.01, min(0.2, deadline - now)))
            return out or b"", err or b"", False
        except subprocess.TimeoutExpired as exc:
            started = True
            out, err = exc.stdout or b"", exc.stderr or b""
    try:
        out, err = proc.communicate(None if started else input, timeout=PIPE_GRACE)
    except subprocess.TimeoutExpired as exc:
        out, err = exc.stdout or b"", exc.stderr or b""
        reap_orphans(_pipe_inodes(proc))
        for pipe in (proc.stdin, proc.stdout, proc.stderr):
            try:
                if pipe is not None:
                    pipe.close()
            except (OSError, ValueError):
                pass
    try:
        proc.wait(timeout=PIPE_GRACE)
    except subprocess.TimeoutExpired:
        pass
    return out or b"", err or b"", timed_out


def kill_all():
    """End every program the tool has running, with what each started. Then everything below the tool itself, which is the tool's own: a
    program forked a moment before it was entered in ACTIVE is among it. Then what an earlier program started and lost (reap_orphans)."""
    for proc in list(ACTIVE):
        kill_tree(proc)
    below = descendants(os.getpid())
    SEEN.update(below)
    for pid in below:
        try:
            os.kill(pid, signal.SIGKILL)
        except OSError:
            pass
    reap_orphans()


def _on_signal(signum, _frame):
    for other in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(other, signal.SIG_IGN)     # the first signal counts: a second one starts no second answer
    kill_all()
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
