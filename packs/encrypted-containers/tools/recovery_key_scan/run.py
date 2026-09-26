#!/usr/bin/env python3
"""Find the key that is already in the evidence.

Almost every container opened in a real case was opened with a key that was
sitting somewhere else in the same case. Attacking the cryptography is the last
resort and usually the wrong one, and this sweep is the first thing to run
instead.

What it looks for:

    a BitLocker recovery password   48 digits in eight groups of six, which is a
                                    distinctive enough shape to find in any text
    a BitLocker key file            .BEK, and the name Windows saves one under
    private keys                    PEM headers, and the id_* file names
    key databases                   keychain, key4.db, login data, kdbx
    the file names people use       "recovery key", "bitlocker", "password"

The 48-digit format carries its own check: each of the eight groups is a
multiple of eleven and below 65536, which removes almost every coincidental
match. Groups that fail the check are still reported, marked, because a partial
transcription is still a lead.

**The values are not printed in full.** A recovered key belongs in the ledger as
a hash and in the operator's hands through whatever channel they named, not in a
report or on a board. Each finding says where it is and what shape it has.
"""
import hashlib
import json
import os
import re
import sys

RECOVERY = re.compile(rb"\b(\d{6})-(\d{6})-(\d{6})-(\d{6})-(\d{6})-(\d{6})-(\d{6})-(\d{6})\b")
UTF16_GROUP = rb"((?:[0-9]\x00){6})"
RECOVERY_UTF16LE = re.compile(
    rb"(?<![0-9]\x00)" + (rb"-\x00".join([UTF16_GROUP] * 8)) + rb"(?![0-9]\x00)"
)
PEM = re.compile(rb"-----BEGIN ([A-Z ]*PRIVATE KEY)-----")
NAME_HINTS = [
    (re.compile(r"\.bek$", re.I), "BitLocker startup key"),
    (re.compile(r"bitlocker.*recovery|recovery.*key", re.I), "a name people save a recovery key under"),
    (re.compile(r"^id_(rsa|dsa|ecdsa|ed25519)$", re.I), "an SSH private key"),
    (re.compile(r"\.kdbx$", re.I), "a KeePass database"),
    (re.compile(r"^key[34]\.db$", re.I), "the Firefox key database"),
    (re.compile(r"^login\.keychain(-db)?$", re.I), "a macOS keychain"),
    (re.compile(r"^FileVaultMaster\.keychain$", re.I), "a FileVault institutional key"),
    (re.compile(r"^Login Data$", re.I), "Chromium saved passwords"),
    (re.compile(r"^logins\.json$", re.I), "Firefox saved passwords"),
    (re.compile(r"\.(ppk|pem|p12|pfx)$", re.I), "a key or certificate store"),
]
SKIP_DIRS = {"proc", "sys", "dev", "__pycache__"}


def fail(message, **extra):
    print(json.dumps({"error": message, **extra}))
    raise SystemExit(1)


def valid_group(value):
    """Each group of a BitLocker recovery password is a multiple of 11 below 65536."""
    try:
        number = int(value)
    except ValueError:
        return False
    return number % 11 == 0 and number // 11 < 65536


def sweep(path, budget):
    findings = []
    try:
        with open(path, "rb") as fh:
            blob = fh.read(budget)
    except OSError:
        return findings
    for found in RECOVERY.finditer(blob):
        groups = [g.decode() for g in found.groups()]
        good = sum(1 for g in groups if valid_group(g))
        findings.append({
            "file": path, "offset": found.start(),
            "kind": "BitLocker recovery password",
            "groups_passing_check": good,
            "complete": good == 8,
            "shape": "-".join("%s****" % g[:2] for g in groups),
            "sha256_of_value": hashlib.sha256(found.group(0)).hexdigest(),
        })
    # Windows' own "save a BitLocker recovery key" dialog writes UTF-16LE
    # text. Searching only ASCII misses the most canonical key file in a case.
    # Hash the canonical displayed value (digits and hyphens), not its on-disk
    # character encoding, so the same recovery password has one fingerprint.
    for found in RECOVERY_UTF16LE.finditer(blob):
        groups = [g.replace(b"\x00", b"").decode("ascii") for g in found.groups()]
        good = sum(1 for g in groups if valid_group(g))
        canonical = "-".join(groups).encode("ascii")
        findings.append({
            "file": path, "offset": found.start(),
            "kind": "BitLocker recovery password",
            "encoding": "UTF-16LE",
            "groups_passing_check": good,
            "complete": good == 8,
            "shape": "-".join("%s****" % g[:2] for g in groups),
            "sha256_of_value": hashlib.sha256(canonical).hexdigest(),
        })
    for found in PEM.finditer(blob):
        findings.append({"file": path, "offset": found.start(), "kind": "private key",
                         "detail": found.group(1).decode("ascii", "replace")})
    return findings


def main():
    try:
        args = json.load(sys.stdin)
    except ValueError as exc:
        fail("arguments are not valid JSON", reason=str(exc))
    path = args.get("path")
    if not isinstance(path, str) or not path:
        fail("path is required: a directory to walk or a blob to sweep")
    if not os.path.exists(path):
        fail("no such file or directory", path=path)
    budget = args.get("max_bytes_per_file", 8 << 20)
    if not isinstance(budget, int) or isinstance(budget, bool) or budget < 1024:
        fail("max_bytes_per_file must be an integer of at least 1024")
    targets = []
    if os.path.isdir(path):
        for dirpath, dirs, names in os.walk(path):
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
            for name in sorted(names):
                targets.append(os.path.join(dirpath, name))
    else:
        targets = [path]

    findings, by_name, scanned, partial_files = [], [], 0, []
    for target in targets:
        base = os.path.basename(target)
        for pattern, meaning in NAME_HINTS:
            if pattern.search(base):
                try:
                    size = os.path.getsize(target)
                except OSError:
                    size = None
                by_name.append({"file": target, "bytes": size, "why": meaning})
                break
        try:
            size = os.path.getsize(target)
        except OSError:
            continue
        if size > budget:
            partial_files.append({"file": target, "bytes": size, "bytes_scanned": budget})
        scanned += 1
        findings.extend(sweep(target, budget))

    complete = sum(1 for f in findings if f.get("complete"))
    print(json.dumps({
        "path": path,
        "files_scanned": scanned,
        "findings": findings,
        "finding_count": len(findings),
        "complete_recovery_passwords": complete,
        "files_worth_opening": by_name,
        "partial_files": partial_files,
        "truncated": False,
        "note": "Values are not printed. Each recovery password is returned as a shape and a hash "
                "of the value; take the file and the offset, read it yourself, and hand the value "
                "to the operator through the channel they named. Record in the report WHERE the "
                "key came from, because the report has to say how you got in. A group that fails "
                "the multiple-of-eleven check is still reported: a partial transcription is a lead.",
    }, indent=2))


if __name__ == "__main__":
    main()
