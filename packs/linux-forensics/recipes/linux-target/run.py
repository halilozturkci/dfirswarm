#!/usr/bin/env python3
"""Recipe protocol for a lossless dissect.target Linux catalogue.

    run.py detect --target T [--probe-out DIR]   exit 0 applies, 1 does not, 2 could not tell
    run.py run --target T --out DIR

detect keeps three answers apart. Exit 0 says dissect.target's `os` function named the target `linux` (its own
identification: nothing here checks it against files in the image). Exit 1 says it named an operating system
this recipe knows is not Linux (windows, osx, esxi, a BSD, android, ios) and so the route is closed. Exit 2 says
it could not tell (the reader is not in this image, it timed out, it failed, it printed nothing, it printed that
it could not identify the system, or it printed a name this recipe does not recognise: `unix`, `debian`, or text
with other words in it) and the route is NOT closed: the census records a detect step that failed, with why,
rather than "does not apply". A reader that is not in the image, or that timed out, is a missing observation
and never a negative. The name is read as one value: the `os` field if the output is a JSON object, the string
if it is a JSON string, the whole line otherwise; a word found among other words is not a name.

Every answer carries `status` (complete, partial or failed) and `status_basis`, the pair coverage.json carries.
For detect, `complete` says the OS was identified (either way) and `failed` says it was not.

run builds the linux_triage artefact files and a coverage receipt that follows what each selected function
produced, read from the wrapper's own durable summary (which the wrapper rewrites after every function), so a
run that is killed or times out still leaves a receipt of what had been done. The receipt is written as
`incomplete` before the wrapper starts, and again if this process is terminated.

Processes. The wrapper, and every program it or detect starts, run in this process's own group, never in a session of
its own: the harness ends a recipe that runs too long, or is aborted, by killing its group, and a program in a group
of its own would go on writing into the output directory after the recipe is gone. SIGTERM, SIGINT and SIGHUP ask the
wrapper to stop (so that it says `terminated` in its summary), kill what is left of its tree, and write the receipt.
detect stops itself at LINUX_TARGET_DETECT_SECONDS (default 240, at most 280 of the harness's 300).
"""

import json
import os
import shutil
import signal
import subprocess
import sys
import time
import traceback
from pathlib import Path

# The harness gives a detect step 300 seconds (`timeout 300`); this one stops itself earlier, whatever the environment says.
MAX_DETECT_SECONDS = 280
try:
    DETECT_SECONDS = min(MAX_DETECT_SECONDS, max(1, int(os.environ.get("LINUX_TARGET_DETECT_SECONDS", "240"))))
except ValueError:
    DETECT_SECONDS = 240
# What dissect.target prints for a system it could not identify, rather than for one it identified.
UNIDENTIFIED = {"default", "unknown", "none", "null", "unidentified", "n/a"}
# Operating systems this recipe knows are not what it catalogues. Anything else that is not `linux` is not a no:
# `unix` or a distribution name may be a Linux this reader did not name so.
NOT_LINUX = {"windows", "osx", "macos", "darwin", "esxi", "bsd", "freebsd", "openbsd", "netbsd", "dragonfly", "android", "ios"}
NOT_COVERED = "deleted/unallocated carving, arbitrary application files, memory, encrypted content without a key"


def answer(value, code=0):
    if value.get("ok") is False and "status" not in value:
        value = {**value, "status": "failed", "status_basis": value.get("error", "the recipe stopped with an error")}
    print(json.dumps(value))
    raise SystemExit(code)


def describe(exc):
    return "%s: %s" % (type(exc).__name__, exc)


# BEGIN SHARED PROCESS
# The same text is in pcap_extract, zeek_run, suricata_run and the network-capture recipe; tests/pack-network-process.test.ts
# holds the copies equal. A program an engine tool runs is started in THIS tool's process group, never in a session of
# its own: the harness ends a tool that runs too long, or is aborted, by killing the tool's group (process.kill(-pid,
# SIGKILL)), and an engine in a group of its own goes on writing into the output directory after the tool is gone. On
# Linux the kernel is also asked to kill it if the tool dies. A deadline kills the program and what it started by
# walking the process tree, and SIGTERM, SIGINT and SIGHUP do the same and then give the tool a last word.
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


def preflight(argv, seconds):
    """Run a short program, bounded; (exit code or None, stdout bytes, stderr bytes, timed out)."""
    try:
        proc = spawn(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except OSError as exc:
        return None, b"", describe(exc).encode("utf-8", "replace"), False
    ACTIVE.append(proc)
    try:
        out, err = proc.communicate(timeout=max(1.0, seconds))
        return proc.returncode, out, err, False
    except subprocess.TimeoutExpired:
        kill_tree(proc)
        out, err = proc.communicate()
        return None, out, err, True
    finally:
        ACTIVE.remove(proc)


def run_to_files(argv, stdout_path, stderr_path, seconds, cwd=None):
    """One program with its output in files, killed with what it started at `seconds`. (exit code, timed out)."""
    with open(stdout_path, "wb") as stdout, open(stderr_path, "wb") as stderr:
        proc = spawn(argv, stdout=stdout, stderr=stderr, cwd=cwd)
        ACTIVE.append(proc)
        try:
            return proc.wait(timeout=max(0.1, seconds)), False
        except subprocess.TimeoutExpired:
            kill_tree(proc)
            proc.wait()
            return None, True
        finally:
            ACTIVE.remove(proc)


def install_signal_handlers():
    for signum in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(signum, _on_signal)
# END SHARED PROCESS


def undetermined(why, code=2):
    answer({"applies": "unknown", "status": "failed", "status_basis": "the OS was not identified, so no route is opened or closed", "why": why}, code)


def write_json(path, value):
    try:
        path.write_text(json.dumps(value, indent=2) + "\n")
    except OSError as exc:
        answer({"ok": False, "status": "failed", "status_basis": "the recipe's own output could not be written", "error": f"could not write {path}: {exc.strerror or exc}"}, 2)


def target_value(raw):
    try:
        value = json.load(open(raw, encoding="utf-8")) if os.path.isfile(raw) else json.loads(raw)
    except (OSError, ValueError) as exc:
        answer({"ok": False, "error": f"target is not readable JSON: {exc}"}, 2)
    paths = value.get("paths") if isinstance(value, dict) else None
    if not isinstance(paths, list) or not paths or not isinstance(paths[0], str):
        answer({"ok": False, "error": "target has no paths"}, 2)
    name = value.get("name")
    return paths[0], name if isinstance(name, str) and name else paths[0]


def detect(image):
    """Any failure to read the OS is exit 2 and `applies: unknown`: only an answer naming a system known not to be Linux closes the route.
    Only a reader that cannot run or answer is a failure of the probe; any other error is a defect in this recipe and is not hidden."""
    try:
        detect_os(image)
    except (OSError, subprocess.SubprocessError, UnicodeError) as exc:    # an unreadable reader, an answer that is not text: not a negative
        undetermined(f"the OS probe failed ({type(exc).__name__}: {exc}): the OS was not identified, so this route is not closed")


def os_name(text):
    """The one value `os` printed, or None: the `os` field of a JSON object, a JSON string, or the whole line. A word among other
    words is not a name (`{"os":"windows","hostname":"linux"}` names windows, and `a linux box` names nothing)."""
    text = text.strip()
    if not text:
        return None
    try:
        value = json.loads(text)
    except ValueError:
        value = text
    if isinstance(value, dict):
        value = value.get("os")
    if not isinstance(value, str):
        return None
    value = value.strip().lower()
    return value if value and len(value.split()) == 1 else None


def detect_os(image):
    binary = shutil.which("target-query")
    if not binary:
        undetermined("target-query is not in this image: the OS of the target was not identified, so this route is not closed")
    install_signal_handlers()
    code, raw_out, raw_err, timed_out = preflight([binary, "--no-cache", "-s", "-f", "os", image], DETECT_SECONDS)
    if timed_out:
        undetermined(f"target-query did not identify the OS within {DETECT_SECONDS} seconds: "
                     "not known to be Linux or not, so this route is not closed")
    stdout, stderr = raw_out.decode("utf-8", "replace"), raw_err.decode("utf-8", "replace")
    if code is None:
        undetermined(f"target-query could not be started ({stderr.strip()[-300:]}): the OS was not identified, so this route is not closed")
    text = stdout.strip()
    first = (text.splitlines() or [""])[0][:80]
    name = os_name(text) if code == 0 else None
    if name == "linux":
        answer({"applies": True, "status": "complete", "status_basis": "dissect.target's os function named the target; that is its own identification, not checked here against files in the image",
                "why": "dissect.target's os function named the target 'linux' (unverified here against the image's files)"})
    if name in NOT_LINUX:
        answer({"applies": False, "status": "complete", "status_basis": "dissect.target's os function named an operating system this recipe knows is not Linux",
                "why": f"dissect.target's os function named the target {name!r}, not Linux"}, 1)
    why = (stderr or stdout).strip()
    if code == 0 and not why:
        why = "target-query exited 0 and printed nothing: the OS was not identified"
    elif code == 0 and name in UNIDENTIFIED:
        why = f"target-query reported that it could not identify the system ({first!r})"
    elif code == 0:
        why = (f"target-query's os function printed {first!r}, which is not a single name this recipe recognises "
               "(linux, or an operating system it knows is not Linux): it is not read as either")
    elif not why:
        why = f"target-query exited {code} without identifying the OS"
    undetermined(why[-400:] + " (the OS was not identified: this route is not closed)")


FUNCTION_STATUSES = ("parsed", "empty", "unsupported", "failed", "not_attempted", "unknown")


def coverage_from(summary, proc_code, shown, state):
    """The receipt: what each selected function produced, from the wrapper's own summary."""
    counts = {k: 0 for k in FUNCTION_STATUSES}
    errors, limits = [], []
    for group in (summary or {}).get("groups") or []:
        for fn in group.get("functions") or []:
            status = fn.get("status")
            if status in counts:
                counts[status] += 1
            if status in ("unsupported", "failed", "not_attempted", "unknown"):
                why = {"unsupported": "the stderr says the function is not available for this target",
                       "failed": f"exit {fn.get('exit_code')}, timed_out={fn.get('timed_out')}",
                       "not_attempted": fn.get("reason", "not started"),
                       "unknown": "its output or stderr could not be read as parsed or empty: read the files"}[status]
                errors.append(f"{group.get('group')}: {fn.get('name')} {status}: {why}")
            if fn.get("timed_out"):
                limits.append(f"{fn.get('name')} timed out ({fn.get('deadline', 'function')} deadline)")
            if status in ("running", "pending"):
                counts["not_attempted"] += 1
                errors.append(f"{group.get('group')}: {fn.get('name')} was {status} when the receipt was written")
    wrapper = (summary or {}).get("state", "missing")
    done = wrapper == "finished" and proc_code == 0 and (summary or {}).get("execution_complete") is True
    clean = done and not any(counts[k] for k in ("unsupported", "failed", "not_attempted", "unknown"))
    total = sum(counts.values())
    ran = counts["parsed"] + counts["empty"] + counts["unsupported"] + counts["unknown"]
    if summary is None:
        status, basis = "failed", "the wrapper left no summary of this run, so what ran is not known"
    elif clean:
        status, basis = "complete", f"every one of the {total} selected functions ran to exit 0 and produced records or nothing: this is not coverage of the host"
    elif ran == 0:
        status, basis = "failed", f"no selected function ran to an exit ({counts['failed']} failed, {counts['not_attempted']} not attempted)"
    else:
        short = ", ".join(f"{counts[k]} {k}" for k in ("unsupported", "failed", "not_attempted", "unknown") if counts[k])
        status, basis = "partial", (f"{ran} of {total} selected functions ran" + (f"; {short}" if short else "")
                                    + ("" if done else "; the wrapper did not end cleanly") + ": the errors say which")
    return {
        "recipe": "linux-target",
        "status": status,
        "status_basis": basis,
        "covered": "the dissect.target functions selected for this recipe (counted under functions, named in artefacts/summary.json) over "
                   + shown + "; `complete` says every selected function ran and produced records or nothing, not that the artefacts exist or were all read",
        "not_covered": NOT_COVERED,
        "functions": counts,
        "limits_hit": limits,
        "errors": errors,
        "wrapper": {"state": wrapper, "exit_code": proc_code, "execution_complete": (summary or {}).get("execution_complete")},
        "receipt_written": state,
    }


def read_summary(out, since):
    """The wrapper's summary, if it is this run's: one that started before this process did is an earlier run's."""
    try:
        summary = json.loads((out / "artefacts" / "summary.json").read_text())
    except (OSError, ValueError):
        return None
    started = summary.get("started") if isinstance(summary, dict) else None
    if not isinstance(started, (int, float)) or started < since:
        return None
    return summary


def write_index(out):
    with (out / "index.tsv").open("w", encoding="utf-8") as index:
        index.write("summary.json\tlinux_triage's answer: per function status, exit code, records, paths, sizes and hashes\n")
        for path in sorted((out / "artefacts").glob("*")) if (out / "artefacts").is_dir() else []:
            if not path.is_file():
                continue
            if path.name == "summary.json":
                kind = "durable summary the wrapper rewrote after every function (state running or finished)"
            elif path.suffix in (".jsonl", ".txt"):
                kind = "complete target-query output of a family's functions, in order"
            else:
                kind = "complete target-query stderr of one function"
            index.write(f"artefacts/{path.name}\t{kind}\n")
        if (out / "runner.stderr").exists():
            index.write("runner.stderr\tcomplete stderr from the linux_triage runner\n")


def run(image, shown, out):
    try:
        out.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        answer({"ok": False, "error": f"the output directory could not be made: {exc.strerror or exc}", "out": str(out)}, 2)
    tool = Path(__file__).resolve().parents[2] / "tools" / "linux_triage" / "run.py"
    # The wrapper runs in the output directory, so that what it makes is under its own working directory whatever this
    # process's was; the image is named by its absolute path for the same reason.
    request = {"source": os.path.abspath(image), "out_dir": "artefacts"}
    state = {"proc": None}
    began = time.time()

    def receipt(proc_code, written):
        summary = read_summary(out, began)
        coverage = coverage_from(summary, proc_code, shown, written)
        write_json(out / "coverage.json", coverage)
        write_index(out)
        return coverage

    # A receipt exists before the wrapper starts, and again if this process is told to stop.
    write_json(out / "coverage.json", {
        "recipe": "linux-target", "status": "partial", "status_basis": "the wrapper had not finished: nothing is established yet",
        "covered": "nothing yet: the wrapper had not finished",
        "not_covered": NOT_COVERED, "errors": ["the wrapper was running when this receipt was written; see artefacts/summary.json"],
        "receipt_written": "before the wrapper started"})

    def terminated(signum, _frame):
        child = state["proc"]
        if child is not None and child.poll() is None:
            # The wrapper is in this process's group, not a session of its own. It is asked to stop first, so that it ends the
            # dissect.target it started and says `terminated` in its summary; whatever is left of its tree is then killed.
            victims = descendants(child.pid)
            try:
                child.terminate()
            except OSError:
                pass
            try:
                child.wait(timeout=8)
            except subprocess.TimeoutExpired:
                pass
            kill_tree(child)
            for pid in victims:
                try:
                    os.kill(pid, signal.SIGKILL)
                except OSError:
                    pass
        receipt(None, "after this process was terminated")
        os._exit(128 + signum)

    for signum in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(signum, terminated)
    try:
        # In this process's own group, never a session of its own: the harness ends a recipe by killing its group.
        proc = spawn([sys.executable, str(tool)], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, cwd=str(out))
    except OSError as exc:
        answer({"ok": False, "status": "failed", "status_basis": "the wrapper could not be started", "error": f"linux_triage could not be started: {exc.strerror or exc}"}, 2)
    state["proc"] = proc
    stdout, stderr = proc.communicate(json.dumps(request))
    try:
        (out / "summary.json").write_text(stdout or json.dumps({"error": "linux_triage wrote no result"}) + "\n")
        if stderr:
            (out / "runner.stderr").write_text(stderr)
    except OSError as exc:
        answer({"ok": False, "status": "failed", "status_basis": "the recipe's own output could not be written", "error": f"could not write the wrapper's answer: {exc.strerror or exc}"}, 2)
    coverage = receipt(proc.returncode, "after the wrapper finished")
    if proc.returncode != 0:
        coverage["errors"].append(f"linux_triage exited {proc.returncode}")
        if coverage["status"] == "complete":
            coverage["status"], coverage["status_basis"] = "partial", f"linux_triage exited {proc.returncode}"
        write_json(out / "coverage.json", coverage)
    answer({"ok": proc.returncode == 0, "status": coverage["status"], "status_basis": coverage["status_basis"], "functions": coverage["functions"]},
           0 if proc.returncode == 0 else 2)


def main():
    command = sys.argv[1] if len(sys.argv) > 1 else ""
    target = None
    out = None
    args = iter(sys.argv[2:])
    for arg in args:
        if arg == "--target":
            target = next(args, None)
        elif arg == "--out":
            out = next(args, None)
        elif arg == "--probe-out":
            next(args, None)
        else:
            answer({"ok": False, "error": f"unknown argument: {arg}"}, 2)
    if not target:
        answer({"ok": False, "error": "--target is required"}, 2)
    image, shown = target_value(target)
    if not os.path.exists(image):
        answer({"ok": False, "error": "target path does not exist"}, 2)
    if command == "detect":
        detect(image)
    if command == "run" and out:
        run(image, shown, Path(out))
    answer({"ok": False, "error": "usage: run.py detect --target T | run --target T --out DIR"}, 2)


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except Exception:
        # A defect in this recipe is shown, not turned into a negative: the traceback is on stderr, and the answer is
        # "could not tell" (exit 2), never exit 1, which says the route is closed.
        traceback.print_exc()
        undetermined("this recipe failed on an unexpected error (the traceback is on its stderr): the OS was not identified, so no route is closed")
