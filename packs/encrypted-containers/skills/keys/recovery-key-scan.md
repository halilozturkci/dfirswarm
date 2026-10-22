---
id: keys/recovery-key-scan
title: What recovery_key_scan shows and does not show
when: You run recovery_key_scan over files, an image or a capture and report what it found.
needs: []
tools: [recovery_key_scan]
requires_host: []
---

Use only if you run `recovery_key_scan` and report what it found. Not for deciding where to look or whether you may (`keys/where-they-hide`).

**recovery_key_scan.** Shows where text in the BitLocker recovery-password format
sits (file, offset, length, ASCII or UTF-16LE, and whether its eight groups pass
the divisible-by-11 check), where a PEM private-key header sits (type and offset),
and which file names are conventional for key files and credential stores. Does
not show: that a value opens anything, what is in a key store, or anything in an
image, an archive or a container (no OCR, no unpacking). It reads the first 8 MiB
of each file unless `max_bytes_per_file` is raised, and lists every file it could
not read, skipped or read only in part: a clean result is bounded by that coverage.
A value is found unless it is glued to more digits (`key_<value>` is found,
`<value>7` is not). A path component shaped like a recovery password, an
identifier or a secret is withheld from the paths it prints (by shape; `paths_withheld`).
At `max_seconds` or on a signal it stops and answers `partial`, naming the files and
directories it did not reach: report those as not searched.
It returns no value, fragment, shape or digest; `write_values: true` is for the one
case that needs the value (`keys/where-they-hide`, Sensitive output).

**Sensitive output.** The scan runs as a job with `secret_output: true`; its answer is a locator, and `write_values: true` (refused outside a job) writes values only to `recovery-passwords.jsonl` under `$OUT`. Cite a finding by file and offset, never by text, and never write a recovery value, a fragment of one, or a hash of one.

**Does not show.** That a value opens anything; what is in a key store; anything in an image, an archive or a container; that a clean result covers the files it did not read or read only in part.

Record: the scan's coverage (`max_bytes_per_file`, the files not read or read in part), each finding's file, offset, length, encoding and structure result.
