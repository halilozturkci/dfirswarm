#!/usr/bin/env python3
"""Recipe protocol for a lossless dissect.target Linux catalogue."""

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path


def answer(value, code=0):
    print(json.dumps(value))
    raise SystemExit(code)


def target_value(raw):
    try:
        value = json.load(open(raw, encoding="utf-8")) if os.path.isfile(raw) else json.loads(raw)
    except (OSError, ValueError) as exc:
        answer({"ok": False, "error": f"target is not readable JSON: {exc}"}, 2)
    paths = value.get("paths") or []
    if not paths or not isinstance(paths[0], str):
        answer({"ok": False, "error": "target has no paths"}, 2)
    return paths[0], value.get("name") or paths[0]


def detect(image):
    binary = shutil.which("target-query")
    if not binary:
        answer({"applies": False, "why": "target-query is not in this image"}, 1)
    try:
        proc = subprocess.run([binary, "--no-cache", "-s", "-f", "os", image],
                              capture_output=True, text=True, timeout=300)
    except subprocess.TimeoutExpired:
        answer({"applies": False, "why": "target-query did not identify the OS within 300 seconds"}, 1)
    text = proc.stdout.strip().lower()
    if proc.returncode == 0 and "linux" in text:
        answer({"applies": True, "why": "dissect.target identified a Linux target"})
    why = (proc.stderr or proc.stdout).strip() or f"target-query exited {proc.returncode} without identifying Linux"
    answer({"applies": False, "why": why}, 1)


def run(image, shown, out):
    out.mkdir(parents=True, exist_ok=True)
    tool = Path(__file__).resolve().parents[2] / "tools" / "linux_triage" / "run.py"
    request = {"source": image, "out_dir": str(out / "artefacts")}
    proc = subprocess.run([sys.executable, str(tool)], input=json.dumps(request),
                          capture_output=True, text=True)
    (out / "summary.json").write_text(proc.stdout or json.dumps({"error": "linux_triage wrote no result"}) + "\n")
    if proc.stderr:
        (out / "runner.stderr").write_text(proc.stderr)
    try:
        summary = json.loads(proc.stdout)
    except ValueError:
        summary = {"complete": False, "error": "linux_triage result was not JSON"}

    with (out / "index.tsv").open("w", encoding="utf-8") as index:
        index.write("summary.json\tlinux_triage manifest: complete output paths, sizes, hashes and statuses\n")
        for path in sorted((out / "artefacts").glob("*")) if (out / "artefacts").is_dir() else []:
            if path.is_file():
                kind = "complete target-query output" if path.suffix in (".jsonl", ".txt") else "complete target-query stderr"
                index.write(f"artefacts/{path.name}\t{kind}\n")
        if (out / "runner.stderr").exists():
            index.write("runner.stderr\tcomplete stderr from the linux_triage runner\n")

    complete = proc.returncode == 0 and summary.get("complete") is True
    errors = []
    for group in summary.get("groups") or []:
        if group.get("exit_code") != 0 or group.get("timed_out"):
            errors.append(f"{group.get('group')}: exit {group.get('exit_code')}, timed_out={group.get('timed_out')}")
    if proc.returncode != 0:
        errors.append(f"linux_triage exited {proc.returncode}")
    coverage = {
        "recipe": "linux-target",
        "status": "complete" if complete else "partial",
        "covered": "selected dissect.target Linux artefact families over " + shown,
        "not_covered": "deleted/unallocated carving, arbitrary application files, memory, encrypted content without a key",
        "limits_hit": [e for e in errors if "timed_out=True" in e],
        "errors": errors,
    }
    (out / "coverage.json").write_text(json.dumps(coverage, indent=2) + "\n")
    answer({"ok": proc.returncode == 0, "status": coverage["status"], "groups": len(summary.get("groups") or [])},
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
    main()
