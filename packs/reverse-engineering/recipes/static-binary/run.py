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


def run_child(script, args, stdout_path, stderr_path, env, timeout):
    """Run a tool with its arguments on stdin and its output going straight to files. Returns (returncode or None, timed_out)."""
    with open(stdout_path, "wb") as out, open(stderr_path, "wb") as err:
        proc = subprocess.Popen([sys.executable, script], stdin=subprocess.PIPE, stdout=out, stderr=err, env=env, start_new_session=True)
        try:
            proc.stdin.write(json.dumps(args).encode("utf-8"))
            proc.stdin.close()
        except OSError:
            pass
        try:
            proc.wait(timeout=timeout)
            return proc.returncode, False
        except subprocess.TimeoutExpired:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except (ProcessLookupError, PermissionError, OSError):
                pass
            proc.kill()
            proc.wait()
            return None, True


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


def run(path, out_dir, fmt):
    os.makedirs(out_dir, exist_ok=True)
    started = time.monotonic()
    env = dict(os.environ)
    # The tools write where $OUT says; a recipe's files belong in its own directory, whatever job called it.
    env["OUT"] = os.path.abspath(out_dir)
    env.pop("JOB_ID", None)
    errors, warnings, limits, omissions = [], [], [], []
    files = {}

    binary = os.path.join(out_dir, "binary.json")
    rc, timed_out = run_child(PE_INFO, {"path": path}, binary, os.path.join(out_dir, "pe_info.stderr"), env, PE_INFO_SECONDS)
    pe_doc, pe_why = read_json(binary)
    pe_status, pe_reason = judge("pe_info", rc, timed_out, pe_doc, pe_why)
    if pe_status != "complete":
        errors.append("pe_info status %s: %s" % (pe_status, pe_reason))
    if pe_doc:
        warnings += [str(p) for p in (pe_doc.get("problems") or [])]
        limits += [str(x) for x in (pe_doc.get("limits_hit") or [])]
        omissions += [str(x) for x in ((pe_doc.get("coverage") or {}).get("structures_not_read") or [])]
        if pe_doc.get("problems_not_listed"):
            warnings.append("%d further problem(s) were counted and not listed by pe_info" % pe_doc["problems_not_listed"])
        for name, table in (pe_doc.get("tables") or {}).items():
            where = table.get("all_results") if isinstance(table, dict) else None
            if where:
                files[os.path.relpath(where, out_dir) if not where.startswith("store/") else where] = "the whole %s table, one JSON row per line (the answer holds the first %s)" % (name, table.get("returned"))

    remaining = BUDGET_SECONDS - (time.monotonic() - started)
    entropy_path = os.path.join(out_dir, "entropy.json")
    if remaining <= 0:
        rc2, timed_out2 = None, True
        open(entropy_path, "wb").close()
    else:
        rc2, timed_out2 = run_child(ENTROPY, {"path": path, "window": ENTROPY_WINDOW, "output_name": ENTROPY_NAME}, entropy_path,
                                    os.path.join(out_dir, "entropy_map.stderr"), env, max(1, int(remaining)))
    en_doc, en_why = read_json(entropy_path)
    en_status, en_reason = judge("entropy_map", rc2, timed_out2, en_doc, en_why)
    if en_status != "complete":
        errors.append("entropy_map status %s: %s" % (en_status, en_reason))
        limits.append("entropy: the pass over the whole file did not finish" if timed_out2 else "entropy: %s" % en_reason)
    profile = (en_doc or {}).get("profile_file")
    runs = (en_doc or {}).get("runs_file")

    usable = [s for s in (pe_status, en_status) if s in ("complete", "partial")]
    if pe_status == "complete" and en_status == "complete":
        status = "complete"
    elif usable:
        status = "partial"
    elif pe_status == "unsupported":
        status = "unsupported"
    else:
        status = "failed"

    for name in ("pe_info.stderr", "entropy_map.stderr"):
        if not drop_if_empty(os.path.join(out_dir, name)):
            files[name] = "what %s said on stderr" % name.split(".")[0]

    coverage = {
        "recipe": "static-binary",
        "target": path,
        "format": fmt,
        "status": status,
        "covered": ("the structures pe_info read (see pe_info.status and omissions) and the whole-file entropy profile "
                    "(entropy_map.status): %s" % ("both read in full" if status == "complete" else "not all of it was read: see errors, warnings and limits_hit")),
        "not_covered": NOT_COVERED,
        "pe_info": {"status": pe_status, "status_basis": pe_reason, "exit_code": rc, "problems": len((pe_doc or {}).get("problems") or [])},
        "entropy_map": {"status": en_status, "status_basis": en_reason, "exit_code": rc2, "windows_measured": (en_doc or {}).get("windows_measured"),
                        "bytes_processed": (en_doc or {}).get("bytes_processed")},
        "limits_hit": limits,
        "warnings": warnings,
        "omissions": omissions,
        "errors": errors,
    }
    with open(os.path.join(out_dir, "coverage.json"), "w", encoding="utf-8") as fh:
        json.dump(coverage, fh, indent=2)
        fh.write("\n")

    lines = []
    if os.path.getsize(binary):
        lines.append("binary.json\tpe_info/2 inventory for %s: status %s, %d problem(s); the structures it read are listed in the file, and what it did not read in coverage.json"
                     % (fmt, pe_status, len((pe_doc or {}).get("problems") or [])))
    if os.path.getsize(entropy_path):
        lines.append("entropy.json\tentropy_map inline summary in %d-byte windows: status %s; the profile is the file named next" % (ENTROPY_WINDOW, en_status))
    if profile and os.path.isfile(os.path.join(out_dir, profile)):
        lines.append("%s\t%s entropy profile, %s windows of %d bytes, one row per window" % (
            profile, "complete" if en_status == "complete" else "partial (%s)" % en_status, (en_doc or {}).get("windows_measured"), ENTROPY_WINDOW))
    if runs and os.path.isfile(os.path.join(out_dir, runs)):
        lines.append("%s\tevery high-entropy run, in the order found" % runs)
    for name, what in files.items():
        if not name.startswith("store/") and os.path.isfile(os.path.join(out_dir, name)):
            lines.append("%s\t%s" % (name, what))
    with open(os.path.join(out_dir, "index.tsv"), "w", encoding="utf-8") as fh:
        fh.write("".join(l + "\n" for l in lines))
    print(json.dumps({"ok": status == "complete", "status": status, "format": fmt}))
    return 0 if status in ("complete", "partial") else 2


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
