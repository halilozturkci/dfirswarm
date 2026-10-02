#!/usr/bin/env python3
"""Add complete text outputs to a private standard-package projection.

Run only after swarm.sh package WITHOUT --redact on the private snapshot.
The run originals are untouched; sensitive directory citations are held
whole in the byte-exact private snapshot, avoiding the observed EISDIR.
Then run the normal package redactor on this writable derivative.
"""
import hashlib
import json
import os
import shutil
import sys
from pathlib import Path

s = Path(sys.argv[1])
out = s / "package"
held_directory = "store/jobs/j000130/out/archive/contact"
text_suffix = {".txt", ".json", ".jsonl", ".md", ".csv", ".tsv", ".log", ".py", ".sh", ".yaml", ".yml", ".xml", ".html"}
count = total = binary = held = 0
for f in sorted((s / "store/jobs").glob("*/out/**/*")):
    if not f.is_file() or f.is_symlink():
        continue
    rel = f.relative_to(s).as_posix()
    if rel.startswith(held_directory + "/"):
        held += 1
        continue
    with open(f, "rb") as h:
        head = h.read(8192)
    if f.suffix.lower() not in text_suffix and b"\0" in head:
        binary += 1
        continue
    dst = out / rel
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(f, dst)
    count += 1
    total += f.stat().st_size
for f in sorted((s / "threads").rglob("*")):
    if f.is_file():
        dst = out / f.relative_to(s)
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(f, dst)
for f in out.rglob("*"):
    if f.is_file():
        os.chmod(f, 0o600)
    elif f.is_dir():
        os.chmod(f, 0o700)
# Regenerate after redaction; these belong to the previous derivative.
for name in ("MANIFEST.txt", "HYGIENE.json"):
    (out / name).unlink(missing_ok=True)
sessions = []
for f in sorted((s / ".pi-sessions").iterdir()):
    if f.is_file():
        b = f.read_bytes()
        sessions.append({"path": str(f.relative_to(s)), "bytes": len(b), "sha256": hashlib.sha256(b).hexdigest(),
                         "retained": str(f), "byte_exact": True})
(out / "PI-SESSION-CUSTODY.json").write_text(json.dumps({"run": "s421201", "kind": "full original sessions retained privately, no trimming or thought-text publication", "files": sessions}, indent=2) + "\n")
(out / "WITHHELD-DIRECTORIES.json").write_text(json.dumps({"run": "s421201", "path": held_directory,
    "cited_sensitive_entries": [207, 209, 213], "files": held, "full_original_directory_retained": str(s / held_directory),
    "why": "sensitive directory-valued refs; normal redactor treats this directory as a file and raises EISDIR"}, indent=2) + "\n")
summary = {"added_full_text_output_files": count, "added_text_output_bytes": total,
    "binary_outputs_retained_private": binary, "sensitive_directory_files_retained_private": held,
    "all_originals_retained_in_private_snapshot": True, "truncated": False}
(s.parent.parent / "supplement-capture.json").write_text(json.dumps(summary, indent=2) + "\n")
print(json.dumps(summary))
