#!/usr/bin/env python3
"""The broad extraction an adb backup would need, declared and not run.

An adb backup keeps each app's data under apps/<package>/ (db/, f/, sp/, r/),
not under the file-system layout (data/data/<package>/databases/) the
artefact parsers in this pack's image read, and no program in the image
turns the one into the other. So the pack declares the capability, says in
recipe.json why it cannot run (`unavailable`), and the harness records the
preparation of every adb backup declined with that why, rather than a parse
that would find next to nothing and read as done.

    run.py detect --target T [--probe-out DIR]   exit 0 an adb backup, 1 not
    run.py run --target T --out DIR              refuses, saying why

Detect reads the backup's header only, as the android-backup recipe does.
"""
import argparse
import json
import os
import sys

MAGIC = b"ANDROID BACKUP\n"
WHY = ("no program in the mobile job image parses an adb backup's app tree (apps/<package>/db, f, sp, r) as a whole: "
       "ALEAPP reads a file-system layout (data/data/<package>/databases), and nothing in the image converts one into the other")


def target_of(value):
    text = open(value, encoding="utf-8").read() if os.path.isfile(value) else value
    target = json.loads(text)
    paths = target.get("paths") or []
    if not paths or not isinstance(paths[0], str):
        raise ValueError("the target names no path")
    return paths[0]


def detect(path):
    try:
        with open(path, "rb") as handle:
            if handle.read(len(MAGIC)) != MAGIC:
                return False, "no Android backup signature"
            version = handle.readline(4096)
            if not version.endswith(b"\n") or not version[:-1].isdigit():
                return False, "Android backup header has no numeric version"
        return True, "an Android adb backup (version %s)" % version[:-1].decode("ascii")
    except OSError as exc:
        return "unknown", "the file could not be read, so it cannot be told whether it is an Android backup: %s" % exc


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("detect", "run"))
    parser.add_argument("--target", required=True)
    parser.add_argument("--out")
    parser.add_argument("--probe-out")
    args = parser.parse_args()
    try:
        path = target_of(args.target)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(json.dumps({"ok": False, "status": "failed", "status_basis": "the target could not be read, so nothing was run", "error": str(exc)}))
        return 2
    if args.command == "detect":
        applies, why = detect(path)
        print(json.dumps({"applies": applies, "why": why}))
        return 2 if applies == "unknown" else 0 if applies else 1
    if args.out:
        os.makedirs(args.out, exist_ok=True)
        with open(os.path.join(args.out, "coverage.json"), "w", encoding="utf-8") as handle:
            json.dump({"recipe": "android-backup-apps", "status": "failed", "status_basis": "this recipe is declared and not run: no program in the image parses an adb backup's app tree",
                       "covered": "nothing: this recipe is declared, not run",
                       "not_covered": "every app's data", "limits_hit": [], "errors": [WHY]}, handle, indent=2, sort_keys=True)
            handle.write("\n")
    print(json.dumps({"ok": False, "status": "failed", "status_basis": "this recipe is declared and not run: no program in the image parses an adb backup's app tree", "why": WHY}))
    return 2


if __name__ == "__main__":
    sys.exit(main())
