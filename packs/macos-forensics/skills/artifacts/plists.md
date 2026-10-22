---
id: artifacts/plists
title: Property lists and structured archives
when: Read persisted values while preserving types, provenance and secret boundaries.
needs: []
tools: [plist_read]
requires_host: []
---

Use when you read a property list and report its keys and values. Not for keyed archives, dates and bare numbers or recent-item records (`artifacts/plists-archives-dates`, only if the file is one of those).

Identify the serialization before parsing: XML, or binary (`bplist00` at offset 0, the usual modern form). A `.plist` name does not establish either. A JSON file beside a plist is not a property list, and a text search of a binary plist's bytes gives keys without their values and values without their keys; `plist_read` reads both encodings with their structure.

    /Library/Preferences/                  machine-wide settings
    ~/Library/Preferences/                 per user, one file per bundle id
    ~/Library/Containers/<id>/Data/…       a sandboxed app's own copy
    /Library/LaunchDaemons, LaunchAgents   configuration, see persistence/mechanisms
    ~/Library/Preferences/com.apple.finder.plist        including recent folders
    /Library/Preferences/com.apple.loginwindow.plist    automatic login, last user

Record the source volume or snapshot, the original path, the key and the parsed value.

**What `plist_read` returns.** Dates as UTC, a UID reference as `{_uid}`, a binary value as its length and kind, and per file a status (parsed, failed, skipped over a bound), so a failure is that file's row, never an empty result. `key` selects a top-level key or a dotted path (an array item by index). `extracted_file_mtime` is the mtime of the file as read, which on an extraction is a copy's: take the original file times from the filesystem metadata. The counts say how many files were matched, parsed, failed, skipped and not reached; read them before saying "none".

**Sensitive output.** A plist can hold a password verifier (account plists), a token or a credential. The tool withholds every binary value and every value under a key named for a secret (verifier, Kerberos keys, password, passphrase, secret, token, credential, private key, pre-shared, auth or access key, cookie, passcode, bearer, one-time password, hint) as a locator, and prints other strings and key names as they are. A file that does not parse is a row with the kind of error and its place, never the file's text. Read account plists and credential-bearing preferences as a job with `secret_output: true`, or select the keys the question needs. `write_values: true` there writes the withheld values (and an error's full message) to a private file under `$OUT`. In the ledger cite the file, key path and finding id, never a value, a fragment or a hash of one.

**Does not show.**
- The effective runtime configuration: `cfprefsd` caches and writes lazily, managed preferences and containers can differ, later changes overwrite earlier ones.
- When a key changed, who changed it, or what it was before. Neither the file's mtime nor a clean shutdown establishes that; corroborate with the unified log, install and update records, or a snapshot.
- Use. For use, go to `artifacts/knowledgec` and `logs/unified`.

Keep complete outputs, parse errors included, in the job's `$OUT`. For a consequential claim cite the original object and the exact key, not the exported JSON.
