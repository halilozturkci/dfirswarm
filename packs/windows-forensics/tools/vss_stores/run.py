#!/usr/bin/env python3
"""List the volume shadow copies on an image.

A shadow copy is a second, older state of the same volume, kept by Windows
itself. It holds the registry hives, the event logs and the files as they were
at the moment the snapshot was taken, which is how a file deleted last week is
still readable today and how a Run key that has since been cleaned is still
there to be found.

This tool LISTS stores (through vshadowinfo) and suggests the command that would
mount them; it mounts nothing, and listing a snapshot does not examine it.
vshadowinfo reads a raw volume or disk image: an E01 has to be exposed as raw first.

The unit trap is worth naming once: mmls and the Sleuth Kit's -o work in
**sectors**, and vshadowinfo's -o works in **bytes**. Passing one where the
other belongs is why this returns "unable to open volume" on an image that is
perfectly sound, so this tool takes bytes and says so in its own output.

The answer is judged, never assumed: vshadowinfo's exit status, its whole standard
output and error (kept in files), the number of stores it says it found against the number
this tool could read, and the output's own header. A failed or unrecognised run is `failed`,
never an answer that there are no stores; "no stores" is said only when vshadowinfo ran,
exited 0 and itself reported zero stores.
"""
import hashlib
import json
import os
import re
import shlex
import shutil
import signal
import subprocess
import sys

TIMEOUT = 240


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
# seconds, and a sandbox that denies both libproc and ps (macOS).
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
            if first is not None and pid in (_children_libproc(os.getpid()) or []):
                return []
            out = subprocess.run(["ps", "-A", "-o", "pid=,ppid="], capture_output=True, text=True, timeout=PS_WAIT).stdout
            for line in out.splitlines():
                parts = line.split()
                if len(parts) == 2 and parts[0].isdigit() and parts[1].isdigit():
                    kids.setdefault(int(parts[1]), []).append(int(parts[0]))
    except (OSError, subprocess.SubprocessError):
        return []
    return _below(kids, pid)


def kill_tree(proc):
    """Kill the program and everything it started. The children are listed first: once the parent is gone they are
    adopted by init and can no longer be found below it. A program already waited for is not touched: its pid is free to
    be another process's, and the walk below it would be that process's children."""
    if proc.poll() is not None:
        return
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
STORE = re.compile(r"^Store:\s*(\d+)\s*$")
FIELD = re.compile(r"^\s+(.+?)\s*:\s*(.*\S)\s*$")


def fail(message, **extra):
    print(json.dumps({"error": message, **extra}))
    raise SystemExit(1)


def key_of(label):
    return re.sub(r"[^a-z0-9]+", "_", label.strip().lower()).strip("_")


def tool_output_dir():
    out, job = os.environ.get("OUT"), os.environ.get("JOB_ID")
    if job and out:
        return os.path.join(out, "tool-output"), "store/jobs/%s/out/tool-output" % re.sub(r"[^A-Za-z0-9_.-]", "_", job)
    d = os.path.join("work", re.sub(r"[^A-Za-z0-9_.-]", "_", os.environ.get("AGENT_ID") or "tool"), "tool-output")
    return d, d


def new_pair(outdir, digest):
    """Two new files, stdout and stderr, named by the arguments' digest and, when an earlier run holds that name, by
    the next free number. Exclusive and never through a link. Returns both descriptors, both paths and the earlier
    files of the same digest, which are left as they are."""
    earlier = sorted(n for n in os.listdir(outdir) if n.startswith("vss_stores-%s" % digest))
    for n in range(1, 1000):
        stem = "vss_stores-%s" % digest + ("" if n == 1 else "-%d" % n)
        out_path = os.path.join(outdir, stem + ".stdout.txt")
        err_path = os.path.join(outdir, stem + ".stderr.txt")
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        try:
            out_fd = os.open(out_path, flags, 0o644)
        except FileExistsError:
            continue
        try:
            err_fd = os.open(err_path, flags, 0o644)
        except FileExistsError:
            os.close(out_fd)
            os.unlink(out_path)
            continue
        return out_fd, err_fd, out_path, err_path, earlier
    raise OSError("no free name for the vshadowinfo output files after 999 tries")


def main():
    install_signal_handlers()
    try:
        args = json.load(sys.stdin)
    except ValueError as exc:
        fail("arguments are not valid JSON", reason=str(exc))

    image = args.get("image")
    if not isinstance(image, str) or not image:
        fail("image is required")
    if not os.path.isfile(image):
        fail("no such image", image=image)

    offset = args.get("offset")
    if offset is not None and (not isinstance(offset, int) or isinstance(offset, bool) or offset < 0):
        fail("offset must be a byte offset, not a sector offset", offset=args.get("offset"))

    # Where a store would be mounted: the seat's own directory. The rest of
    # work/ is read-only in a VM, and a mount is that VM's alone either way.
    mount_dir = args.get("mount_dir")
    if mount_dir is None:
        mount_dir = "work/%s/vss" % (os.environ.get("AGENT_ID") or "<your id>")
    elif not isinstance(mount_dir, str) or not mount_dir:
        fail("mount_dir must be a directory path", mount_dir=mount_dir)
    mount_dir = mount_dir.rstrip("/")

    if not shutil.which("vshadowinfo"):
        fail("vshadowinfo is not on PATH",
             install="brew install libvshadow, or apt-get install -y libvshadow-utils")

    argv = ["vshadowinfo"]
    if offset is not None:
        argv += ["-o", str(offset)]
    argv.append(image)
    try:
        with open(image, "rb") as fh:
            head = fh.read(8)
    except OSError as exc:
        fail("the image could not be read", image=image, reason=str(exc))
    outdir, shown = tool_output_dir()
    digest = hashlib.sha256(json.dumps(argv).encode("utf-8")).hexdigest()[:16]
    try:
        os.makedirs(outdir, exist_ok=True)
        # Created, never opened over: a run with the same arguments keeps its own pair of files, and an earlier
        # run's stay as they were (the next free number names the new pair).
        out_fd, err_fd, out_path, err_path, earlier = new_pair(outdir, digest)
    except OSError as exc:
        fail("the files for vshadowinfo's output could not be created in %s" % shown, reason=str(exc))
    def interrupted(signum):
        print(json.dumps({"error": "stopped by signal %d before vshadowinfo finished" % signum, "status": "interrupted", "signal": signum,
                          "stdout_file": out_path, "stderr_file": err_path,
                          "note": "No statement about shadow copies follows from an interrupted run."}), flush=True)

    STATE["last_word"] = interrupted
    with os.fdopen(out_fd, "wb") as so, os.fdopen(err_fd, "wb") as se:
        try:
            proc = spawn(argv, stdout=so, stderr=se)
        except OSError as exc:
            fail("vshadowinfo could not be started: %s" % exc, reason=type(exc).__name__)
        rc, timed_out = wait_for(proc, TIMEOUT)

    with open(out_path, "r", encoding="utf-8", errors="replace") as fh:
        text = fh.read()
    with open(err_path, "r", encoding="utf-8", errors="replace") as fh:
        stderr = fh.read().strip()
    stores, current = [], None
    for line in text.splitlines():
        m = STORE.match(line)
        if m:
            current = {"store": int(m.group(1))}
            stores.append(current)
            continue
        if current is None:
            continue
        m = FIELD.match(line)
        if m:
            current[key_of(m.group(1))] = m.group(2)

    claimed = None
    m = re.search(r"Number of stores:\s*(\d+)", text)
    if m:
        claimed = int(m.group(1))

    mountable = shutil.which("vshadowmount") is not None
    for store in stores:
        mkdir_argv = ["mkdir", "-p", mount_dir]
        mount_argv = ["vshadowmount"] + (["-o", str(offset)] if offset is not None else []) + [image, mount_dir + "/"]
        store["mount_argv"] = [mkdir_argv, mount_argv]
        store["mount_with"] = "%s && %s  # then %s/vss%d" % (shlex.join(mkdir_argv), shlex.join(mount_argv), mount_dir, store["store"])

    problems = []
    if timed_out:
        problems.append("vshadowinfo was stopped after %d seconds" % TIMEOUT)
    elif rc != 0:
        problems.append("vshadowinfo exited with status %d" % rc)
    if rc == 0 and claimed is None:
        problems.append("vshadowinfo's output has no 'Number of stores' line; this tool does not recognise its format")
    if claimed is not None and claimed != len(stores):
        problems.append("vshadowinfo reports %d store(s) and %d could be read from its output" % (claimed, len(stores)))
    if head == b"EVF\x09\x0d\x0a\xff\x00":
        problems.append("the image starts with the EWF (E01) signature: vshadowinfo reads raw data, so expose the image raw first")

    if problems and (rc != 0 or timed_out or claimed is None):
        status = "failed"
    elif problems:
        status = "partial"
    else:
        status = "complete"

    out = {
        "parser": "vss_stores/4",
        "status": status,
        "image": image,
        "offset_bytes": offset,
        "mount_dir": mount_dir,
        "stores": stores,
        "store_count": len(stores),
        "stores_claimed": claimed,
        "problems": problems,
        "vshadowmount_present": mountable,
        "exit_code": rc,
        "timed_out": timed_out,
        "command": shlex.join(argv),
        "stdout_file": "%s/%s" % (shown, os.path.basename(out_path)),
        "stderr_file": "%s/%s" % (shown, os.path.basename(err_path)),
        "earlier_output_files": ["%s/%s" % (shown, n) for n in earlier],
        "vshadowinfo_stderr_lines": len(stderr.splitlines()),
        "vshadowinfo_said": stderr.splitlines()[:5],
    }
    if status == "failed":
        out["error"] = "vshadowinfo did not give a usable answer: " + "; ".join(problems)
        out["note"] = ("This is a failure, not a finding: no statement about shadow copies on this volume follows from it, and "
                       "'no stores' must not be reported. Check the offset (BYTES, not sectors), that this is a raw volume or image, and the "
                       "stderr file; then ask again.")
        print(json.dumps(out, indent=2))
        raise SystemExit(1)
    if not stores:
        out["note"] = ("vshadowinfo, run on this image at offset %s, reported 0 stores. That says no store was found in this volume's metadata "
                       "as this reader parsed it. It does not establish that none was ever made or that one was deleted: correlate the host's "
                       "age and configuration with event logs, command history and free-space evidence before saying why no store is present."
                       % (offset if offset is not None else "0 (none given)"))
    elif status == "partial":
        out["note"] = "The list above is incomplete: " + "; ".join(problems) + ". Do not count the stores from it."
    elif not mountable:
        out["note"] = ("vshadowmount is not installed, so the stores cannot be opened here. "
                       "The list above, with the creation times, still belongs in the timeline.")
    else:
        out["note"] = ("Listing is not mounting, and a listed store is not an examined one. To open one, run the mount_argv commands (a FUSE mount "
                       "may be unavailable in a worker), then run the ordinary toolkit against %s/vssN as if it were a volume. The mount is yours alone: "
                       "copy what you derive from it into your own directory and record it. A hive or a log read there is the state at "
                       "the store's creation time, not at acquisition: cite both times." % mount_dir)
    print(json.dumps(out, indent=2))


if __name__ == "__main__":
    try:
        main()
    except OSError as exc:
        fail("a file operation failed: %s" % exc, reason=type(exc).__name__)
