#!/usr/bin/env python3
"""Recipe protocol for the Windows artefacts of an extracted collection (or of artefacts named one by one).

    run.py detect --target T [--probe-out DIR]   exit 0 applies, 1 does not, 2 could not tell
    run.py run --target T --out DIR

TARGET is JSON (inline or a file path): {"paths": [...], "ref": ..., "name": ...}. Every path is a directory (an extracted
collection, walked, links not followed) or a file (a hive, an event log, a prefetch file, a link, a jump list, $MFT, $J, an
ESE database, a browser history database). Nothing here is a parser: each family is read by the tool of this pack that reads
it, once per input, and the whole answer of every call is kept.

detect says whether the target holds an artefact of a family this recipe reads. A directory is walked for at most
WINDOWS_ARTEFACTS_DETECT_SECONDS (default 120, at most 280 of the harness's 300) and the answer says if it was cut short: a
walk that ran out of time and found nothing is `could not tell` (exit 2), never `does not apply`. A file is classified by its
name and its first bytes.

run reads each family in turn and writes, under DIR, one directory per family (`results.jsonl`: one line per tool call with
its arguments, exit code and the whole answer; the files the tools wrote are beside it), an `index.tsv` naming every file, and
`coverage.json`. The status of a family is
  parsed         every input of the family was read and the tool said complete;
  partial        some inputs were read and some were not, or a tool said partial (counts say which);
  empty          the tool ran and found no record in what it read;
  unsupported    the tool refused the input as not what it reads;
  failed         the tool failed on every input (or was killed by its time limit);
  not_attempted  nothing of the family was in the collection, the recipe's time was used, or the tool is not in this pack;
`complete` for the whole run means every family with an input was parsed or empty and no family was cut short: it is not
coverage of the host. Registry hives are handed to registry_recover with the transaction logs found beside them in the
collection, named in the family's results. When the target is one directory and target-query (dissect.target) is installed, a
fixed list of its functions that read what no tool of this pack does is run one call each (stdout and stderr of every call kept
whole in files); a function the installed version does not have is `unsupported`, and a missing target-query is `not_attempted`
with that reason. Plaso is not run (the base pack's disk-timeline recipe runs it over a disk image).

Processes. Every tool runs in this process's own group, never a session of its own, so the harness ending the recipe by killing
its group ends them; SIGTERM, SIGINT and SIGHUP end the running tool, write the receipt as `incomplete` and exit 128 + the signal.
"""
import json
import os
import re
import shutil
import signal
import stat
import subprocess
import sys
import time
import traceback
from pathlib import Path

# The harness gives a detect step 300 seconds; this one stops itself earlier, whatever the environment says.
MAX_DETECT_SECONDS = 280
try:
    DETECT_SECONDS = min(MAX_DETECT_SECONDS, max(1, int(os.environ.get("WINDOWS_ARTEFACTS_DETECT_SECONDS", "120"))))
except ValueError:
    DETECT_SECONDS = 120
MAX_WALK_ENTRIES = 2_000_000
RUN_SECONDS = 3300                  # recipe.json allows 3600; no call is started past this
PER_CALL_CAP = 600
NOT_COVERED = ("Plaso (not run by this recipe), PowerShell block reassembly / WMI repository / $LogFile (no reader in this pack), the semantic joins of "
               "UserAssist / BAM / ShimCache / SRUM (only dissect.target's own output, when it is installed), deleted and unallocated data, volume shadow copies, memory")

HIVE_NAMES = {"system", "software", "sam", "security", "default", "ntuser.dat", "usrclass.dat", "amcache.hve", "components", "drivers", "bbi", "elam"}
ESE_NAMES = {"srudb.dat", "webcachev01.dat"}
SQLITE_MAGIC = b"SQLite format 3\x00"
EVTX_MAGIC = b"ElfFile\x00"
REGF_MAGIC = b"regf"
SCCA_MAGICS = (b"SCCA", b"MAM\x04")
ESE_MAGIC_AT_4 = b"\xef\xcd\xab\x89"


def answer(value, code=0):
    if value.get("ok") is False and "status" not in value:
        value = {**value, "status": "failed", "status_basis": value.get("error", "the recipe stopped with an error")}
    print(json.dumps(value))
    raise SystemExit(code)


def describe(exc):
    return "%s: %s" % (type(exc).__name__, exc)


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


# ---- classifying a file -------------------------------------------------------------------------------------------------------

def head_of(path, n=16):
    """The first bytes of a regular file. A pipe, a socket or a device is never read (it is opened without waiting, and only to be refused)."""
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_CLOEXEC", 0))
    except OSError:
        return b""
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            return b""
        return os.read(fd, n)
    except OSError:
        return b""
    finally:
        os.close(fd)


USN_NAMES = ("$j", "$usnjrnl$j", "usnjrnl_j", "$usnjrnl_$j")
BROWSER_NAMES = ("history", "places.sqlite")


def in_recycle_bin(path):
    parts = [p.lower() for p in Path(path).parts]
    return any(p.startswith("$recycle.bin") or p == "recycler" for p in parts[:-1])


def classify(path):
    """The family a file belongs to, by its name and then, for the families whose name is not enough, its first bytes; or None.
    The bytes of a file whose name is none of the names below are not read."""
    low = os.path.basename(path).lower()
    if low.endswith(".lnk") or low.endswith("destinations-ms"):
        return "shortcuts-jumplists"
    if low == "$mft":
        return "mft"
    if low in HIVE_NAMES:
        return "registry-hives" if head_of(path)[:4] == REGF_MAGIC else None
    if low.endswith(".pf"):
        head = head_of(path)
        return "prefetch" if (head[:4] in SCCA_MAGICS or head[4:8] == b"SCCA") else None
    if low.endswith(".evtx"):
        return "event-logs" if head_of(path)[:8] == EVTX_MAGIC else None
    if low in ESE_NAMES:
        return "esedb" if head_of(path)[4:8] == ESE_MAGIC_AT_4 else None
    if low in USN_NAMES:
        return "usn-journal" if head_of(path) else None
    if low.startswith("$i") and in_recycle_bin(path):
        return "recycle-bin" if len(head_of(path)) >= 8 else None
    if low in BROWSER_NAMES:
        return "browser-history" if head_of(path)[:16] == SQLITE_MAGIC else None
    return None


def walk(paths, deadline):
    """[(family, absolute path)] for every file under the paths, links not followed; (found, cut short, entries seen)."""
    found, seen, cut = [], 0, False
    for top in paths:
        top = os.path.abspath(top)
        if os.path.isfile(top):
            seen += 1
            family = classify(top)
            if family:
                found.append((family, top))
            continue
        for root, dirs, files in os.walk(top, followlinks=False):
            dirs.sort()
            if time.monotonic() > deadline:
                cut = True
                break
            for name in sorted(files):
                seen += 1
                if seen > MAX_WALK_ENTRIES:
                    cut = True
                    break
                full = os.path.join(root, name)
                try:
                    if not stat.S_ISREG(os.lstat(full).st_mode):
                        continue      # a link is not followed; a pipe, a socket or a device is not read
                except OSError:
                    continue
                family = classify(full)
                if family:
                    found.append((family, full))
            if cut:
                break
        if cut:
            break
    return found, cut, seen


def target_value(raw):
    try:
        value = json.load(open(raw, encoding="utf-8")) if os.path.isfile(raw) else json.loads(raw)
    except (OSError, ValueError) as exc:
        answer({"ok": False, "error": "target is not readable JSON: %s" % describe(exc)}, 2)
    paths = value.get("paths") if isinstance(value, dict) else None
    if not isinstance(paths, list) or not paths or not all(isinstance(p, str) and p for p in paths):
        answer({"ok": False, "error": "target has no paths"}, 2)
    name = value.get("name")
    return paths, name if isinstance(name, str) and name else paths[0]


def detect(paths):
    deadline = time.monotonic() + DETECT_SECONDS
    for p in paths:
        if not os.path.exists(p):
            answer({"applies": "unknown", "status": "failed", "status_basis": "a target path does not exist, so nothing was examined", "why": "a target path does not exist"}, 2)
    found, cut, seen = walk(paths, deadline)
    families = sorted({f for f, _ in found})
    if families:
        answer({"applies": True, "status": "complete" if not cut else "partial",
                "status_basis": "found artefact files of %d family(ies) among %d entries%s" % (len(families), seen, "; the walk was cut short, so others may exist" if cut else ""),
                "why": "the target holds Windows artefact files this recipe reads: %s (%d file(s))" % (", ".join(families), len(found))})
    if cut:
        answer({"applies": "unknown", "status": "failed", "status_basis": "the walk of the target ended at its time or entry limit before it found an artefact, so nothing is closed",
                "why": "examined %d entries in %d seconds without finding a Windows artefact; the rest was not examined" % (seen, DETECT_SECONDS)}, 2)
    answer({"applies": False, "status": "complete", "status_basis": "every file of the target was classified by name and first bytes",
            "why": "none of %d entries is a registry hive, event log, prefetch file, link, jump list, $MFT, $J, SRUM or WebCache database, $I file or browser history database" % seen}, 1)


# ---- running the tools --------------------------------------------------------------------------------------------------------

TOOLS_DIR = Path(__file__).resolve().parents[2] / "tools"


def tool_timeout(tool):
    try:
        return int(json.load(open(TOOLS_DIR / tool / "manifest.json")).get("timeout_seconds", 120))
    except (OSError, ValueError):
        return 120


def run_tool(tool, args, cwd, seconds):
    """One call of a tool of this pack. Returns (exit code or None, the answer or None, stdout text, stderr text, timed out, why)."""
    entry = TOOLS_DIR / tool / "run.py"
    if not entry.is_file():
        return None, None, "", "", False, "the tool %s is not in this pack" % tool
    env = dict(os.environ)
    env.setdefault("AGENT_ID", "windows-artefacts")
    try:
        proc = spawn([sys.executable, str(entry)], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=str(cwd), env=env)
    except OSError as exc:
        return None, None, "", "", False, "the tool could not be started: %s" % describe(exc)
    ACTIVE.append(proc)
    try:
        out, err = proc.communicate(json.dumps(args).encode("utf-8"), timeout=max(1.0, seconds))
        timed_out = False
    except subprocess.TimeoutExpired:
        kill_tree(proc)
        out, err = proc.communicate()
        timed_out = True
    finally:
        if proc in ACTIVE:
            ACTIVE.remove(proc)
    text = out.decode("utf-8", "replace")
    parsed = None
    try:
        parsed = json.loads(text)
    except ValueError:
        pass
    return (None if timed_out else proc.returncode), parsed, text, err.decode("utf-8", "replace")[-2000:], timed_out, None


def beside(path, suffixes):
    """The files beside `path` whose name is its name plus one of the suffixes, matched without regard to case."""
    directory, name = os.path.split(path)
    try:
        listing = os.listdir(directory)
    except OSError:
        return {}
    wanted = {name.lower() + s.lower(): s for s in suffixes}
    return {wanted[f.lower()]: os.path.join(directory, f) for f in listing if f.lower() in wanted}


def minimal_directories(files):
    """The fewest directories that hold all the files: a directory whose ancestor is already in the set is left out."""
    dirs = sorted({os.path.dirname(f) for f in files}, key=lambda d: (d.count(os.sep), d))
    kept = []
    for d in dirs:
        if not any(d == k or d.startswith(k + os.sep) for k in kept):
            kept.append(d)
    return kept


def calls_for(family, files):
    """[(label, tool, args)] for a family's files."""
    if family == "registry-hives":
        out = []
        for f in files:
            logs = beside(f, [".LOG1", ".LOG2"])
            args = {"hive": f, "limit": 1}
            if ".LOG1" in logs:
                args["log1"] = logs[".LOG1"]
            if ".LOG2" in logs:
                args["log2"] = logs[".LOG2"]
            out.append((f, "registry_recover", args))
        return out
    if family == "shortcuts-jumplists":
        return [(d, "lnk_jumplist", {"path": d, "limit": 1}) for d in minimal_directories(files)]
    if family == "prefetch":
        return [(f, "prefetch_mam", {"path": f}) for f in files]
    if family == "event-logs":
        return [(f, "evtx_query", {"path": f, "limit": 1}) for f in files]
    if family == "recycle-bin":
        return [(d, "recyclebin_i", {"path": d, "limit": 1}) for d in minimal_directories(files)]
    if family == "mft":
        return [(f, "mft_records", {"path": f, "limit": 1}) for f in files]
    if family == "usn-journal":
        return [(f, "usn_journal", {"path": f, "limit": 1}) for f in files]
    if family == "esedb":
        return [(f, "esedb_query", {"path": f, "limit": 1}) for f in files]
    if family == "browser-history":
        out = []
        for f in files:
            queries = ("firefox_visits", "firefox_downloads") if os.path.basename(f).lower() == "places.sqlite" else ("chrome_visits", "chrome_downloads")
            out += [(f + " [" + q + "]", "browser_history", {"path": f, "query": q, "limit": 1}) for q in queries]
        return out
    return []


EXTRA_CALLS = {
    "amcache": ("registry-hives", lambda f: os.path.basename(f).lower() == "amcache.hve", "amcache_apps", lambda f: {"hive": f, "limit": 1}),
    "shellbags": ("registry-hives", lambda f: os.path.basename(f).lower() in ("ntuser.dat", "usrclass.dat"), "shellbags", lambda f: {"hive": f, "limit": 1}),
}

FAMILIES = ["registry-hives", "amcache", "shellbags", "prefetch", "shortcuts-jumplists", "event-logs", "recycle-bin", "mft", "usn-journal", "esedb", "browser-history"]
DISSECT_FUNCTIONS = ["userassist", "bam", "shimcache", "srum", "services", "runkeys", "tasks"]   # what no tool of this pack reads
DISSECT_FUNCTION_SECONDS = 900
NOT_RUN = {
    "plaso": "Plaso is not run by this recipe: the disk-timeline recipe of the base pack runs it over a disk image, and a directory of extracted artefacts is not a source it takes",
}


def dissect_stage(paths, out, deadline, limits):
    """The functions of dissect.target that read what no tool of this pack does, one call each, over a target that is one directory.
    Returns the family's receipt entry. Every call's whole stdout and stderr are kept in files; nothing here reads a record."""
    fam = {"tool": "target-query", "inputs": 0, "calls": 0, "counts": {"parsed": 0, "partial": 0, "empty": 0, "unsupported": 0, "failed": 0, "not_attempted": 0}}
    binary = shutil.which("target-query")
    if not binary:
        fam.update(status="not_attempted", reason="target-query (dissect.target) is not installed in this image, so none of its functions was run")
        return fam
    if len(paths) != 1 or not os.path.isdir(paths[0]):
        fam.update(status="not_attempted", reason="dissect.target opens one target, and this target is not exactly one directory, so none of its functions was run")
        return fam
    help_text = ""
    try:
        help_text = subprocess.run([binary, "--help"], capture_output=True, timeout=60, text=True, errors="replace").stdout
    except (OSError, subprocess.SubprocessError):
        pass
    fam["inputs"] = 1
    fam["version_output"] = None
    try:
        fam["version_output"] = subprocess.run([binary, "--version"], capture_output=True, timeout=60, text=True, errors="replace").stdout.strip()[:300] or None
    except (OSError, subprocess.SubprocessError):
        pass
    json_flag = ["--json"] if "--json" in help_text else []
    fam["records_format"] = "one JSON object per line" if json_flag else "the program's default text form (this version lists no --json)"
    fdir = out / "dissect-target"
    fdir.mkdir(exist_ok=True)
    with (fdir / "results.jsonl").open("w", encoding="utf-8") as results:
        for name in DISSECT_FUNCTIONS:
            fam["calls"] += 1
            if time.monotonic() > deadline:
                fam["counts"]["not_attempted"] += 1
                limits.append("dissect-target: %s was not started: the recipe's own time was used" % name)
                results.write(json.dumps({"input": paths[0], "tool": "target-query", "function": name, "state": "not_attempted", "why": "the recipe's own time was used"}) + "\n")
                continue
            argv = [binary, "-f", name] + json_flag + [paths[0]]
            out_file, err_file = fdir / (name + ".out"), fdir / (name + ".stderr")
            timed_out, code = False, None
            with out_file.open("wb") as o, err_file.open("wb") as e:
                try:
                    proc = spawn(argv, stdout=o, stderr=e)
                except OSError as exc:
                    code, timed_out = None, False
                    e.write(("could not be started: %s\n" % describe(exc)).encode())
                else:
                    ACTIVE.append(proc)
                    try:
                        code = proc.wait(timeout=max(1.0, min(DISSECT_FUNCTION_SECONDS, deadline - time.monotonic())))
                    except subprocess.TimeoutExpired:
                        kill_tree(proc)
                        proc.wait()
                        timed_out = True
                    finally:
                        if proc in ACTIVE:
                            ACTIVE.remove(proc)
            size = out_file.stat().st_size
            try:
                err_text = err_file.read_bytes()[-4000:].decode("utf-8", "replace")
            except OSError:
                err_text = ""
            records = None
            if json_flag and size:
                with out_file.open("rb") as fh:
                    records = sum(1 for line in fh if line.strip())
            if timed_out or code is None:
                state = "failed"
                limits.append("dissect-target: %s was killed at its time limit" % name)
            elif code != 0:
                state = "unsupported" if re.search(r"unknown (plugin|function)|no (such )?(plugin|function)|PluginNotFound|not a valid (plugin|function)|invalid choice|unrecognized arguments", err_text, re.I) else "failed"
            elif size == 0:
                state = "empty"
            else:
                state = "parsed"
            fam["counts"][state] += 1
            results.write(json.dumps({"input": paths[0], "tool": "target-query", "function": name, "argv": argv[:-1] + ["<target>"], "exit_code": code, "timed_out": timed_out,
                                      "state": state, "records": records, "stdout_bytes": size, "stdout_file": "dissect-target/" + out_file.name,
                                      "stderr_file": "dissect-target/" + err_file.name}) + "\n")
    c = fam["counts"]
    total = sum(c.values())
    if c["not_attempted"] == total:
        fam["status"], fam["reason"] = "not_attempted", "no function was started (the recipe's own time was used)"
    elif c["failed"] + c["unsupported"] == total:
        fam["status"], fam["reason"] = ("unsupported" if c["unsupported"] == total else "failed"), "no function produced a result (see results.jsonl and the .stderr files)"
    elif c["parsed"] + c["empty"] == total:
        fam["status"], fam["reason"] = ("empty" if c["empty"] == total else "parsed"), "every function exited 0"
    else:
        fam["status"], fam["reason"] = "partial", "functions ended: " + ", ".join("%d %s" % (v, k) for k, v in c.items() if v)
    return fam


def recovered_path(shown, cwd):
    """The file a registry_recover answer names as its recovered copy, as this process can open it: in a job the answer says
    store/jobs/<job>/out/<rest> and the file is at $OUT/<rest>; outside a job the name is from the tool's working directory."""
    if not isinstance(shown, str) or not shown:
        return None
    out = os.environ.get("OUT")
    m = re.fullmatch(r"store/jobs/[A-Za-z0-9_.-]+/out/(.+)", shown)
    path = Path(out) / m.group(1) if (m and out and os.environ.get("JOB_ID")) else Path(cwd) / shown
    return str(path) if path.is_file() and not path.is_symlink() else None


def judge(answer_json, code, timed_out):
    """(state, records) of one call: parsed, partial, empty, unsupported or failed, from what the tool said."""
    if timed_out or code is None:
        return "failed", None
    if not isinstance(answer_json, dict):
        return "failed", None
    if code != 0:
        error = str(answer_json.get("error", ""))
        if re.search(r"not a (LNK|hive|regf)|not an? .*(file|database|header)|signature|not a registry|is not an|no jump list files|neither", error, re.I):
            return "unsupported", None
        return "failed", None
    status = answer_json.get("status")
    records = None
    for key in ("entry_count", "event_count", "matched", "records_read", "count", "link_count", "nodes_listed", "keys"):
        value = answer_json.get(key)
        if isinstance(value, int) and not isinstance(value, bool):
            records = value
            break
    if isinstance(answer_json.get("records"), dict):
        value = answer_json["records"].get("keys")
        if isinstance(value, int):
            records = value
    if status == "partial":
        return "partial", records
    if records == 0:
        return "empty", 0
    return "parsed", records


def main_run(paths, shown, out):
    try:
        out.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        answer({"ok": False, "error": "the output directory could not be made: %s" % describe(exc), "out": str(out)}, 2)
    began = time.monotonic()
    deadline = began + RUN_SECONDS
    receipt = {"recipe": "windows-artefacts", "status": "partial", "status_basis": "the recipe had not finished: nothing is established yet", "covered": "nothing yet",
               "not_covered": NOT_COVERED, "families": {}, "errors": [], "receipt_written": "before the first tool ran"}

    def write_receipt(state):
        receipt["receipt_written"] = state
        try:
            (out / "coverage.json").write_text(json.dumps(receipt, indent=2) + "\n")
            write_index()
        except OSError as exc:
            answer({"ok": False, "status": "failed", "status_basis": "the recipe's own output could not be written", "error": "could not write the receipt: %s" % describe(exc)}, 2)

    def write_index():
        with (out / "index.tsv").open("w", encoding="utf-8") as index:
            index.write("coverage.json\tper family: status, why, tool, inputs, counts of parsed/partial/empty/unsupported/failed calls\n")
            for p in sorted(out.rglob("*")):
                if p.is_file() and p.name not in ("index.tsv", "coverage.json") and not p.name.startswith("."):
                    rel = p.relative_to(out).as_posix()
                    index.write("%s\t%s\n" % (rel, "one line per tool call: its arguments, exit code and whole answer" if p.name == "results.jsonl" else "written by the tool of the family"))

    write_receipt("before the first tool ran")

    def stopped(signum, _frame):
        for proc in list(ACTIVE):
            kill_tree(proc)
        receipt["status"], receipt["status_basis"] = "partial", "the recipe was terminated by signal %d before it finished: the families below are what had been read" % signum
        write_receipt("after this process was terminated")
        os._exit(128 + signum)

    for signum in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(signum, stopped)

    found, cut, seen = walk(paths, deadline)
    by_family = {}
    for family, full in found:
        by_family.setdefault(family, []).append(full)
    for fam in by_family.values():
        fam.sort()
    receipt["walk"] = {"entries_seen": seen, "files_found": len(found), "cut_short": cut}
    plan = {}
    for fid in FAMILIES:
        if fid in EXTRA_CALLS:
            parent, pick, tool, mk = EXTRA_CALLS[fid]
            files = [f for f in by_family.get(parent, []) if pick(f)]
            plan[fid] = (tool, [(f, tool, mk(f)) for f in files], files)
        else:
            files = by_family.get(fid, [])
            calls = calls_for(fid, files)
            plan[fid] = (calls[0][1] if calls else None, calls, files)
    limits = []
    recovered = {}      # hive path -> the recovered copy registry_recover made of it, when it replayed something
    for fid in FAMILIES:
        tool, calls, files = plan[fid]
        fam = {"tool": tool or {"registry-hives": "registry_recover"}.get(fid), "inputs": len(files), "calls": len(calls), "counts": {"parsed": 0, "partial": 0, "empty": 0, "unsupported": 0, "failed": 0, "not_attempted": 0}}
        receipt["families"][fid] = fam
        if not calls:
            fam["status"] = "not_attempted"
            fam["reason"] = "no file of this family is in the target" + ("; the walk was cut short, so one may exist unseen" if cut else "")
            continue
        fdir = out / fid
        fdir.mkdir(exist_ok=True)
        with (fdir / "results.jsonl").open("w", encoding="utf-8") as results:
            for label, tool_name, args in calls:
                if time.monotonic() > deadline:
                    fam["counts"]["not_attempted"] += 1
                    limits.append("%s: %s was not started: the recipe's own time (%d seconds) was used" % (fid, label, RUN_SECONDS))
                    results.write(json.dumps({"input": label, "tool": tool_name, "state": "not_attempted", "why": "the recipe's own time was used"}) + "\n")
                    continue
                seconds = min(PER_CALL_CAP, tool_timeout(tool_name) + 15, max(1.0, deadline - time.monotonic()))
                note = None
                if fid in EXTRA_CALLS and args.get("hive") in recovered:
                    # The hive was dirty and registry_recover replayed its logs: the other hive tools read that copy, and the row says so.
                    note = "read from the recovered copy of %s made by registry_recover (the original is dirty; this is a derivative)" % args["hive"]
                    args = {**args, "hive": recovered[args["hive"]]}
                code, parsed, text, err, timed_out, why = run_tool(tool_name, args, fdir, seconds)
                if tool_name == "registry_recover" and isinstance(parsed, dict) and parsed.get("replayed") is True:
                    copy = recovered_path(parsed.get("recovered_copy"), fdir)
                    if copy:
                        recovered[args["hive"]] = copy
                if why:
                    state = "not_attempted"
                    fam["counts"]["not_attempted"] += 1
                    results.write(json.dumps({"input": label, "tool": tool_name, "state": state, "why": why}) + "\n")
                    continue
                state, records = judge(parsed, code, timed_out)
                fam["counts"][state] += 1
                if timed_out:
                    limits.append("%s: %s was killed at %d seconds" % (fid, label, int(seconds)))
                row = {"input": label, "tool": tool_name, "arguments": args, "note": note, "exit_code": code, "timed_out": timed_out, "state": state, "records": records,
                       "answer": parsed if parsed is not None else text, "stderr_tail": err or None}
                results.write(json.dumps(row) + "\n")
        c = fam["counts"]
        total = sum(c.values())
        if c["not_attempted"] == total:
            fam["status"], fam["reason"] = "not_attempted", "no call was made (time used or the tool is not in this pack)"
        elif c["failed"] == total:
            fam["status"], fam["reason"] = "failed", "every call failed (see results.jsonl)"
        elif c["unsupported"] == total:
            fam["status"], fam["reason"] = "unsupported", "the tool refused every input as not what it reads"
        elif c["empty"] == total:
            fam["status"], fam["reason"] = "empty", "the tool ran and found no record in what it read"
        elif c["parsed"] + c["empty"] == total:
            fam["status"], fam["reason"] = "parsed", "every call ended complete"
        else:
            fam["status"], fam["reason"] = "partial", "calls ended: " + ", ".join("%d %s" % (v, k) for k, v in c.items() if v)
        write_receipt("after family %s" % fid)
    receipt["families"]["dissect-target"] = dissect_stage(paths, out, deadline, limits)
    write_receipt("after family dissect-target")
    for fid, why in NOT_RUN.items():
        receipt["families"][fid] = {"tool": None, "inputs": 0, "calls": 0, "status": "not_attempted", "reason": why, "counts": {}}
    statuses = [f["status"] for f in receipt["families"].values() if f["inputs"]]
    bad = [k for k, f in receipt["families"].items() if f["inputs"] and f["status"] not in ("parsed", "empty")]
    receipt["limits_hit"] = limits
    if cut:
        receipt["errors"].append("the walk of the target was cut short: files may exist that were not seen")
    if not statuses and cut:
        receipt["status"], receipt["status_basis"] = "failed", "the walk of the target was cut short before it found an artefact of a family this recipe reads, so nothing is established"
    elif not statuses:
        receipt["status"], receipt["status_basis"] = "failed", "the target held no artefact of a family this recipe reads"
    elif bad or cut or limits:
        receipt["status"] = "partial"
        receipt["status_basis"] = "%d of %d families with an input were parsed or empty%s%s" % (
            len(statuses) - len(bad), len(statuses), ("; not: " + ", ".join("%s (%s)" % (k, receipt["families"][k]["status"]) for k in bad)) if bad else "",
            "; the walk was cut short" if cut else "")
    else:
        receipt["status"] = "complete"
        receipt["status_basis"] = "every family with an input in the target was read by its tool and ended parsed or empty (%d); the families not run are named: this is not coverage of the host" % len(statuses)
    receipt["covered"] = "the files of %s found in %s by name and first bytes, each read by the tool of this pack for it" % (", ".join(sorted(k for k in FAMILIES if receipt["families"][k]["inputs"])) or "no family", shown) + ("; and the dissect.target functions listed in the receipt over the target directory" if receipt["families"]["dissect-target"]["inputs"] else "")
    write_receipt("after the last family")
    answer({"ok": receipt["status"] != "failed", "status": receipt["status"], "status_basis": receipt["status_basis"],
            "families": {k: v["status"] for k, v in receipt["families"].items()}}, 0 if receipt["status"] != "failed" else 2)


def main():
    command = sys.argv[1] if len(sys.argv) > 1 else ""
    target = out = None
    args = iter(sys.argv[2:])
    for arg in args:
        if arg == "--target":
            target = next(args, None)
        elif arg == "--out":
            out = next(args, None)
        elif arg == "--probe-out":
            next(args, None)
        else:
            answer({"ok": False, "error": "unknown argument: %s" % arg}, 2)
    if not target:
        answer({"ok": False, "error": "--target is required"}, 2)
    paths, shown = target_value(target)
    if command == "detect":
        install_signal_handlers()
        detect(paths)
    if command == "run" and out:
        if not all(os.path.exists(p) for p in paths):
            answer({"ok": False, "error": "a target path does not exist"}, 2)
        main_run(paths, shown, Path(out))
    answer({"ok": False, "error": "usage: run.py detect --target T | run --target T --out DIR"}, 2)


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except Exception:
        traceback.print_exc()
        answer({"applies": "unknown", "status": "failed", "status_basis": "this recipe failed on an unexpected error (the traceback is on its stderr)", "why": "unexpected error"}, 2)
