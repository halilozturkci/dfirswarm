#!/usr/bin/env python3
"""Catalogue one PE, ELF or Mach-O file using this pack's static tools."""
import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
PACK = os.path.abspath(os.path.join(HERE, "..", ".."))
PE_INFO = os.path.join(PACK, "tools", "pe_info", "run.py")
ENTROPY = os.path.join(PACK, "tools", "entropy_map", "run.py")


def target_of(arg):
    text = open(arg, encoding="utf-8").read() if os.path.isfile(arg) else arg
    target = json.loads(text)
    paths = target.get("paths") or []
    if not paths or not isinstance(paths[0], str):
        raise ValueError("the target names no path")
    return target, paths[0]


def detect(path):
    try:
        with open(path, "rb") as fh:
            head = fh.read(4)
            if head[:2] == b"MZ":
                fh.seek(0x3C)
                raw = fh.read(4)
                if len(raw) != 4:
                    return None, "MZ header is too short to name a PE signature"
                pe_at = int.from_bytes(raw, "little")
                fh.seek(pe_at)
                if fh.read(4) == b"PE\x00\x00":
                    return "PE", "DOS header points to a PE signature"
                return None, "MZ header does not point to a PE signature"
    except OSError as exc:
        return None, "unreadable: %s" % (exc.strerror or exc)
    if head == b"\x7fELF":
        return "ELF", "ELF signature"
    if head in (b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe", b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca"):
        return "Mach-O", "Mach-O signature"
    return None, "no PE, ELF or Mach-O signature"


def run_tool(script, path, out_path, extra=None):
    args = {"path": path, **(extra or {})}
    proc = subprocess.run(
        [sys.executable, script], input=json.dumps(args), text=True,
        capture_output=True
    )
    with open(out_path, "w", encoding="utf-8") as fh:
        fh.write(proc.stdout)
    return proc.returncode, proc.stderr


def run(path, out_dir, fmt):
    os.makedirs(out_dir, exist_ok=True)
    errors = []
    rc, err = run_tool(PE_INFO, path, os.path.join(out_dir, "binary.json"))
    if rc:
        errors.append("pe_info exited %d: %s" % (rc, err.strip()))
    rc, err = run_tool(ENTROPY, path, os.path.join(out_dir, "entropy.json"), {"window": 65536})
    if rc:
        errors.append("entropy_map exited %d: %s" % (rc, err.strip()))
    status = "complete" if not errors else "failed"
    coverage = {
        "recipe": "static-binary",
        "target": path,
        "format": fmt,
        "status": status,
        "covered": "static headers, sections, imports or linked libraries, and whole-file entropy",
        "not_covered": "execution, unpacking, decompilation, signature verification, or observed behaviour",
        "limits_hit": [],
        "errors": errors,
    }
    with open(os.path.join(out_dir, "coverage.json"), "w", encoding="utf-8") as fh:
        json.dump(coverage, fh, indent=2)
    with open(os.path.join(out_dir, "index.tsv"), "w", encoding="utf-8") as fh:
        if os.path.getsize(os.path.join(out_dir, "binary.json")):
            fh.write("binary.json\tcomplete static structure for %s\n" % fmt)
        if os.path.getsize(os.path.join(out_dir, "entropy.json")):
            fh.write("entropy.json\twhole-file Shannon entropy profile in 65536-byte windows\n")
    print(json.dumps({"ok": status == "complete", "status": status, "format": fmt}))
    return 0 if status == "complete" else 2


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
            json.dump({"recipe": "static-binary", "status": "unsupported", "why": why,
                       "limits_hit": [], "errors": []}, fh, indent=2)
        print(json.dumps({"ok": False, "status": "unsupported", "why": why}))
        return 2
    return run(path, args["--out"], fmt)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
