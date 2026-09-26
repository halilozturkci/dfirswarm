#!/usr/bin/env python3
"""Find the notes, and pull out the identifiers a response actually needs.

The note is the one artefact the operator wants you to read, which makes it the
easiest to find and the most useful to parse. Four things come out of it:

    the onion address or portal   which identifies the group
    the victim identifier         which a negotiator cannot proceed without
    contact addresses             email, session, qtox, telegram
    wallet addresses              for the financial-crime referral

Where the note was dropped matters as much as what it says. A copy in every
directory the encryptor touched maps its reach, and the earliest copy's
modification time is close to when the run started on that machine.

The contents are identifiers, not narrative: quote the identifier, keep the
rhetoric in an appendix, and do not follow any link from inside the evidence.
"""
import datetime
import hashlib
import json
import os
import re
import sys

NAME_HINTS = re.compile(
    r"(readme|read_me|decrypt|restore|recover|unlock|how[\W_]*to|ransom|help[\W_]*|"
    r"your[\W_]*files|instruction|_note|!!!)", re.I)
ONION = re.compile(r"\b([a-z2-7]{16}|[a-z2-7]{56})\.onion\b", re.I)
EMAIL = re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]{2,}\b")
URL = re.compile(r"\bhttps?://[^\s<>\"')]{6,200}")
BITCOIN = re.compile(r"\b(?:bc1[ac-hj-np-z02-9]{11,71}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b")
MONERO = re.compile(r"\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b")
ETHEREUM = re.compile(r"\b0x[a-fA-F0-9]{40}\b")
IDENTIFIER = re.compile(
    r"(?:your\s+(?:personal\s+)?(?:id|key|token)|victim\s*id|company\s*id|"
    r"identifier|decryption\s*id)\s*[:=\-]?\s*([A-Za-z0-9\-_]{8,80})", re.I)
TOX = re.compile(r"\b[A-F0-9]{76}\b", re.I)


def fail(message, **extra):
    print(json.dumps({"error": message, **extra}))
    raise SystemExit(1)


def main():
    try:
        args = json.load(sys.stdin)
    except ValueError as exc:
        fail("arguments are not valid JSON", reason=str(exc))
    root = args.get("root")
    if not isinstance(root, str) or not root:
        fail("root is required: a directory to sweep")
    if not os.path.isdir(root):
        fail("no such directory", root=root)
    max_size = args.get("max_size", 200000)
    if not isinstance(max_size, int) or isinstance(max_size, bool) or max_size < 16:
        fail("max_size must be an integer of at least 16")
    limit = args.get("limit", 100)
    if not isinstance(limit, int) or isinstance(limit, bool) or limit < 1:
        fail("limit must be a positive integer")

    notes, digests = [], {}
    onions, emails, urls, wallets, identifiers, toxes = set(), set(), set(), set(), set(), set()
    scanned = note_count = 0
    earliest = None
    out_dir = os.environ.get("OUT")
    complete_path = None
    complete = None
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)
        complete_path = os.path.join(out_dir, "ransom-notes.jsonl")
        complete = open(complete_path, "w", encoding="utf-8")
    for dirpath, dirs, names in os.walk(root):
        dirs[:] = [d for d in dirs if d not in ("proc", "sys", "dev")]
        for name in sorted(names):
            if not NAME_HINTS.search(name):
                continue
            full = os.path.join(dirpath, name)
            try:
                size = os.path.getsize(full)
            except OSError:
                continue
            if size > max_size or size == 0:
                continue
            try:
                with open(full, "rb") as fh:
                    blob = fh.read(max_size)
            except OSError:
                continue
            scanned += 1
            text = blob.decode("utf-8", "replace")
            if "\x00" in text[:200]:
                text = blob.decode("utf-16-le", "replace")
            found = {
                "onion": sorted({m.group(0) for m in ONION.finditer(text)}),
                "email": sorted(set(EMAIL.findall(text))),
                "url": sorted({u for u in URL.findall(text)}),
                "bitcoin": sorted(set(BITCOIN.findall(text))),
                "monero": sorted(set(MONERO.findall(text))),
                "ethereum": sorted(set(ETHEREUM.findall(text))),
                "tox": sorted(set(TOX.findall(text))),
                "identifier": sorted({m.group(1) for m in IDENTIFIER.finditer(text)}),
            }
            onions.update(found["onion"]); emails.update(found["email"])
            urls.update(found["url"]); identifiers.update(found["identifier"])
            toxes.update(found["tox"])
            wallets.update(found["bitcoin"] + found["monero"] + found["ethereum"])
            digest = hashlib.sha256(blob).hexdigest()
            digests[digest] = digests.get(digest, 0) + 1
            try:
                modified = datetime.datetime.fromtimestamp(
                    os.path.getmtime(full), datetime.timezone.utc).isoformat().replace("+00:00", "Z")
            except OSError:
                modified = None
            note = {"file": full, "bytes": size, "modified": modified,
                    "sha256": digest,
                    "identifiers": {k: v for k, v in found.items() if v},
                    "first_lines": [l.strip() for l in text.splitlines() if l.strip()][:4]}
            note_count += 1
            if modified and (earliest is None or modified < earliest):
                earliest = modified
            if complete:
                complete.write(json.dumps(note, sort_keys=True) + "\n")
                if len(notes) < limit:
                    notes.append(note)
            else:
                notes.append(note)

    if complete:
        complete.close()

    variants = [{"sha256": h, "copies": c} for h, c in
                sorted(digests.items(), key=lambda kv: -kv[1])]
    print(json.dumps({
        "root": root,
        "notes": notes,
        "note_count": note_count,
        "notes_complete": complete_path is None or len(notes) == note_count,
        "notes_file": os.path.basename(complete_path) if complete_path else None,
        "files_examined": scanned,
        "distinct_notes": variants,
        "earliest_note_modified": earliest,
        "onion_addresses": sorted(onions),
        "contact_emails": sorted(emails),
        "urls": sorted(urls),
        "wallets": sorted(wallets),
        "tox_ids": sorted(toxes),
        "victim_identifiers": sorted(identifiers),
        "note": "The victim identifier is what a negotiator cannot proceed without, and the onion "
                "address is what identifies the group. Quote the identifiers and keep the "
                "rhetoric in an appendix. Do NOT open any link found here from the examination "
                "host: visiting a leak site or a portal can identify the victim to the operator "
                "and is a decision for the organisation, not for the examiner. The earliest note "
                "modification time is close to when the run started on this machine.",
    }, indent=2))


if __name__ == "__main__":
    main()
