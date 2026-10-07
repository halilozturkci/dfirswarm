#!/usr/bin/env python3
"""Catalogue one PE, ELF or Mach-O file using this pack's static tools.

Two passes, each run as the tool the agent would run, each writing its output straight into a file of this
recipe's directory: `pe_info` (the structure it read) and `entropy_map` (the complete entropy profile). The
recipe's status is the parsers' own statement of what they read, never an exit code and never "the output
file is not empty": a parser that exits 0 with a header problem is `partial` here, and the index says so.

    complete      pe_info read every structure it reads, and the entropy pass finished
    partial       at least one pass produced a usable result and something was not read: coverage.json says
                  which structure, which parser and why (warnings, limits_hit, errors, omissions)
    unsupported   the file is not one this recipe applies to
    failed        neither pass produced a usable result

Applicability (`detect`) is judged from enough structure to tell an executable from a coincident magic prefix:
a PE needs its signature where the DOS header points; an ELF needs a class, a byte order and a whole header
(52 or 64 bytes); a thin Mach-O needs its whole header; a universal binary needs a plausible architecture table
whose first slice starts with a Mach-O magic (a Java class file begins with the same word).

The recipe reads the file; it executes nothing.
"""
import json
import os
import signal
import struct
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
PACK = os.path.abspath(os.path.join(HERE, "..", ".."))
PE_INFO = os.path.join(PACK, "tools", "pe_info", "run.py")
ENTROPY = os.path.join(PACK, "tools", "entropy_map", "run.py")

BUDGET_SECONDS = 570                      # recipe.json gives this recipe 600
PE_INFO_SECONDS = 240
ENTROPY_WINDOW = 65536
ENTROPY_NAME = "entropy-windows.tsv"
MACHO_THIN = {b"\xce\xfa\xed\xfe": 28, b"\xcf\xfa\xed\xfe": 32, b"\xfe\xed\xfa\xce": 28, b"\xfe\xed\xfa\xcf": 32}
FAT = {b"\xca\xfe\xba\xbe": (">", 20), b"\xbe\xba\xfe\xca": ("<", 20), b"\xca\xfe\xba\xbf": (">", 32), b"\xbf\xba\xfe\xca": ("<", 32)}
MAX_JSON = 256 << 20
NOT_COVERED = "execution, unpacking, decompilation, signature verification, or observed behaviour"


def target_of(arg):
    text = open(arg, encoding="utf-8").read() if os.path.isfile(arg) else arg
    target = json.loads(text)
    paths = target.get("paths") or []
    if not paths or not isinstance(paths[0], str):
        raise ValueError("the target names no path")
    return target, paths[0]


def detect(path):
    """(format or None, why)."""
    try:
        size = os.path.getsize(path)
        with open(path, "rb") as fh:
            head = fh.read(64)
            magic = head[:4]
            if head[:2] == b"MZ":
                if len(head) < 0x40:
                    return None, "MZ header is too short to name a PE signature"
                pe_at = int.from_bytes(head[0x3C:0x40], "little")
                fh.seek(pe_at)
                if fh.read(4) == b"PE\x00\x00":
                    return "PE", "DOS header points to a PE signature"
                return None, "MZ header does not point to a PE signature"
            if magic == b"\x7fELF":
                if len(head) < 6 or head[4] not in (1, 2):
                    return None, "ELF signature with an EI_CLASS that is neither ELFCLASS32 nor ELFCLASS64"
                if head[5] not in (1, 2):
                    return None, "ELF signature with an EI_DATA that is neither little- nor big-endian"
                need = 64 if head[4] == 2 else 52
                if size < need:
                    return None, "ELF signature, and the file is shorter than an ELF%d header (%d bytes)" % (64 if need == 64 else 32, need)
                return "ELF", "ELF signature and a whole ELF header"
            if magic in MACHO_THIN:
                if size < MACHO_THIN[magic]:
                    return None, "Mach-O signature, and the file is shorter than its header (%d bytes)" % MACHO_THIN[magic]
                return "Mach-O", "Mach-O signature and a whole header"
            if magic in FAT:
                e, entry = FAT[magic]
                if size < 8 + entry:
                    return None, "universal-binary signature, and the file is shorter than one architecture entry"
                nfat = struct.unpack(e + "I", head[4:8])[0]
                if not 1 <= nfat <= 256:
                    return None, ("the universal-binary magic with %d slices declared is not a plausible architecture table "
                                  "(0xCAFEBABE is also the first word of a Java class file)" % nfat)
                fh.seek(8)
                row = fh.read(entry)
                if entry == 20:
                    offset, length = struct.unpack(e + "II", row[8:16])
                else:
                    offset, length = struct.unpack(e + "QQ", row[8:24])
                if offset + length > size or length < 4:
                    return None, ("the first slice of this universal-binary header lies outside the file "
                                  "(0xCAFEBABE is also the first word of a Java class file)")
                fh.seek(offset)
                if fh.read(4) not in MACHO_THIN:
                    return None, "the first slice does not begin with a Mach-O magic (0xCAFEBABE is also the first word of a Java class file)"
                return "Mach-O", "universal-binary signature, a plausible architecture table and a Mach-O first slice"
    except OSError as exc:
        return None, "unreadable: %s" % (exc.strerror or exc)
    return None, "no PE, ELF or Mach-O signature"


def describe(exc):
    return "%s: %s" % (type(exc).__name__, getattr(exc, "strerror", None) or str(exc))


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


def run_child(script, args, stdout_path, stderr_path, env, timeout):
    """Run a tool with its arguments on stdin and its output going straight to files, in THIS recipe's process group.
    Returns (returncode or None, timed_out). A deadline ends the tool and what it started."""
    with open(stdout_path, "wb") as out, open(stderr_path, "wb") as err:
        proc = spawn([sys.executable, script], stdin=subprocess.PIPE, stdout=out, stderr=err, env=env)
        ACTIVE.append(proc)
        try:
            try:
                proc.stdin.write(json.dumps(args).encode("utf-8"))
                proc.stdin.close()
            except OSError:
                pass
            try:
                return proc.wait(timeout=max(0.1, timeout)), False
            except subprocess.TimeoutExpired:
                kill_tree(proc)
                proc.wait()
                return None, True
        finally:
            ACTIVE.remove(proc)


def read_json(path):
    try:
        if os.path.getsize(path) > MAX_JSON:
            return None, "the output is larger than %d bytes" % MAX_JSON
        with open(path, encoding="utf-8") as fh:
            value = json.load(fh)
    except (OSError, ValueError) as exc:
        return None, "not JSON (%s)" % exc
    return (value, None) if isinstance(value, dict) else (None, "not a JSON object")


def drop_if_empty(path):
    try:
        if os.path.isfile(path) and os.path.getsize(path) == 0:
            os.unlink(path)
            return True
    except OSError:
        pass
    return False


def judge(label, rc, timed_out, doc, why):
    """The parser's own status: (status, reason). A missing or unreadable answer is `failed`."""
    if timed_out:
        return "failed", "%s was stopped at its time limit" % label
    if doc is None:
        return "failed", "%s returned no readable answer: %s (exit %s)" % (label, why, rc)
    status = doc.get("status")
    if status not in ("complete", "partial", "failed", "unsupported"):
        return "failed", "%s's answer carries no status, so what it read cannot be judged (exit %s)" % (label, rc)
    return status, doc.get("status_basis") or doc.get("error") or ""


def pass_state(label):
    return {"label": label, "status": "failed", "reason": "%s has not run" % label, "rc": None, "doc": None}


def assemble(state):
    """The recipe's result from what the passes have said so far: (status, coverage, index lines). A pass that has not
    run counts as failed with that reason, so a recipe that is stopped says exactly this."""
    out_dir, fmt, path = state["out_dir"], state["fmt"], state["path"]
    pe, en = state["pe"], state["en"]
    errors, warnings, limits, omissions = list(state["errors"]), [], [], []
    files = {}
    for st in (pe, en):
        if st["status"] != "complete":
            errors.append("%s status %s: %s" % (st["label"], st["status"], st["reason"]))
    pe_doc, en_doc = pe["doc"], en["doc"]
    if pe_doc:
        warnings += [str(p) for p in (pe_doc.get("problems") or [])]
        limits += [str(x) for x in (pe_doc.get("limits_hit") or [])]
        omissions += [str(x) for x in ((pe_doc.get("coverage") or {}).get("structures_not_read") or [])]
        if pe_doc.get("problems_not_listed"):
            warnings.append("%d further problem(s) were counted and not listed by pe_info" % pe_doc["problems_not_listed"])
        for name, table in (pe_doc.get("tables") or {}).items():
            where = table.get("all_results") if isinstance(table, dict) else None
            if where:
                files[os.path.relpath(where, out_dir) if not where.startswith("store/") else where] = (
                    "the whole %s table, one JSON row per line (the answer holds the first %s)" % (name, table.get("returned")))
    if en["status"] != "complete":
        limits.append("entropy: the pass over the whole file did not finish" if en.get("timed_out") else "entropy: %s" % en["reason"])
    profile = (en_doc or {}).get("profile_file")
    runs = (en_doc or {}).get("runs_file")

    usable = [st["status"] for st in (pe, en) if st["status"] in ("complete", "partial")]
    if pe["status"] == "complete" and en["status"] == "complete" and not state["errors"]:
        status = "complete"
    elif usable:
        status = "partial"
    elif pe["status"] == "unsupported":
        status = "unsupported"
    else:
        status = "failed"

    coverage = {
        "recipe": "static-binary",
        "target": path,
        "format": fmt,
        "status": status,
        "covered": ("the structures pe_info read (see pe_info.status and omissions) and the whole-file entropy profile "
                    "(entropy_map.status): %s" % ("both read in full" if status == "complete" else "not all of it was read: see errors, warnings and limits_hit")),
        "not_covered": NOT_COVERED,
        "pe_info": {"status": pe["status"], "status_basis": pe["reason"], "exit_code": pe["rc"], "problems": len((pe_doc or {}).get("problems") or [])},
        "entropy_map": {"status": en["status"], "status_basis": en["reason"], "exit_code": en["rc"], "windows_measured": (en_doc or {}).get("windows_measured"),
                        "bytes_processed": (en_doc or {}).get("bytes_processed")},
        "limits_hit": limits,
        "warnings": warnings,
        "omissions": omissions,
        "errors": errors,
    }
    lines = []
    binary, entropy_path = os.path.join(out_dir, "binary.json"), os.path.join(out_dir, "entropy.json")
    if os.path.isfile(binary) and os.path.getsize(binary):
        lines.append("binary.json\tpe_info/2 inventory for %s: status %s, %d problem(s); the structures it read are listed in the file, and what it did not read in coverage.json"
                     % (fmt, pe["status"], len((pe_doc or {}).get("problems") or [])))
    if os.path.isfile(entropy_path) and os.path.getsize(entropy_path):
        lines.append("entropy.json\tentropy_map inline summary in %d-byte windows: status %s; the profile is the file named next" % (ENTROPY_WINDOW, en["status"]))
    if profile and os.path.isfile(os.path.join(out_dir, profile)):
        lines.append("%s\t%s entropy profile, %s windows of %d bytes, one row per window" % (
            profile, "complete" if en["status"] == "complete" else "partial (%s)" % en["status"], (en_doc or {}).get("windows_measured"), ENTROPY_WINDOW))
    if runs and os.path.isfile(os.path.join(out_dir, runs)):
        lines.append("%s\tevery high-entropy run, in the order found" % runs)
    for name in ("pe_info.stderr", "entropy_map.stderr"):
        if os.path.isfile(os.path.join(out_dir, name)) and os.path.getsize(os.path.join(out_dir, name)):
            files[name] = "what %s said on stderr" % name.split(".")[0]
    for name, what in files.items():
        if not name.startswith("store/") and os.path.isfile(os.path.join(out_dir, name)):
            lines.append("%s\t%s" % (name, what))
    return status, coverage, lines


def write_results(state):
    status, coverage, lines = assemble(state)
    out_dir = state["out_dir"]
    for name in ("coverage.json", "index.tsv"):
        tmp = os.path.join(out_dir, name + ".new")
        with open(tmp, "w", encoding="utf-8") as fh:
            if name == "coverage.json":
                json.dump(coverage, fh, indent=2)
                fh.write("\n")
            else:
                fh.write("".join(l + "\n" for l in lines))
        os.replace(tmp, os.path.join(out_dir, name))
    return status


def run(path, out_dir, fmt):
    os.makedirs(out_dir, exist_ok=True)
    started = time.monotonic()
    env = dict(os.environ)
    # The tools write where $OUT says; a recipe's files belong in its own directory, whatever job called it.
    env["OUT"] = os.path.abspath(out_dir)
    env.pop("JOB_ID", None)
    state = {"out_dir": out_dir, "fmt": fmt, "path": path, "errors": [], "pe": pass_state("pe_info"), "en": pass_state("entropy_map")}

    def last_word(signum):
        # Stopped by a signal: the running passes are ended (the handler did that); coverage and the index say where it stopped.
        state["errors"].append("the recipe was stopped by signal %d; the passes that were running were ended" % signum)
        try:
            write_results(state)
        except OSError:
            pass

    STATE["last_word"] = last_word
    install_signal_handlers()
    # From the first moment there is a coverage.json that says the recipe has not finished: a recipe ended without a last
    # word (SIGKILL) still leaves one.
    state["errors"].append("the recipe was started and has not finished")
    write_results(state)
    state["errors"].pop()

    binary = os.path.join(out_dir, "binary.json")
    rc, timed_out = run_child(PE_INFO, {"path": path}, binary, os.path.join(out_dir, "pe_info.stderr"), env, min(PE_INFO_SECONDS, BUDGET_SECONDS))
    doc, why = read_json(binary)
    status, reason = judge("pe_info", rc, timed_out, doc, why)
    state["pe"] = {"label": "pe_info", "status": status, "reason": reason, "rc": rc, "doc": doc, "timed_out": timed_out}
    state["errors"].append("the recipe was started and has not finished")
    write_results(state)
    state["errors"].pop()

    remaining = BUDGET_SECONDS - (time.monotonic() - started)
    entropy_path = os.path.join(out_dir, "entropy.json")
    if remaining <= 0:
        rc2, timed_out2 = None, True
        open(entropy_path, "wb").close()
    else:
        rc2, timed_out2 = run_child(ENTROPY, {"path": path, "window": ENTROPY_WINDOW, "output_name": ENTROPY_NAME}, entropy_path,
                                    os.path.join(out_dir, "entropy_map.stderr"), env, remaining)
    doc2, why2 = read_json(entropy_path)
    status2, reason2 = judge("entropy_map", rc2, timed_out2, doc2, why2)
    state["en"] = {"label": "entropy_map", "status": status2, "reason": reason2, "rc": rc2, "doc": doc2, "timed_out": timed_out2}
    final = write_results(state)
    print(json.dumps({"ok": final == "complete", "status": final, "format": fmt}))
    return 0 if final in ("complete", "partial") else 2


def main(argv):
    if len(argv) < 2 or argv[1] not in ("detect", "run"):
        print(json.dumps({"ok": False, "error": "usage: run.py detect --target T | run --target T --out DIR"}))
        return 2
    args = dict(zip(argv[2::2], argv[3::2]))
    if "--target" not in args:
        print(json.dumps({"ok": False, "error": "--target is required"}))
        return 2
    try:
        _target, path = target_of(args["--target"])
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(json.dumps({"ok": False, "error": str(exc)}))
        return 2
    if not os.path.isfile(path):
        print(json.dumps({"ok": False, "error": "the target is not a readable file"}))
        return 2
    fmt, why = detect(path)
    if argv[1] == "detect":
        print(json.dumps({"applies": fmt is not None, "format": fmt, "why": why}))
        return 0 if fmt else 1
    if "--out" not in args:
        print(json.dumps({"ok": False, "error": "run needs --out DIR"}))
        return 2
    if fmt is None:
        os.makedirs(args["--out"], exist_ok=True)
        with open(os.path.join(args["--out"], "coverage.json"), "w", encoding="utf-8") as fh:
            json.dump({"recipe": "static-binary", "status": "unsupported", "why": why, "limits_hit": [], "errors": []}, fh, indent=2)
        print(json.dumps({"ok": False, "status": "unsupported", "why": why}))
        return 2
    return run(path, args["--out"], fmt)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
