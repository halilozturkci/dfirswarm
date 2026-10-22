---
id: logs/journal
title: Journal coverage and record identity
when: Examining supplied systemd journals without losing fields or boot coverage.
needs: []
tools: [journal_export]
requires_host: [journalctl]
---

Use when you read a systemd journal from the evidence. Not for clock order and `--verify` (`logs/journal-clocks-verify`, only if you order entries or judge integrity) or for auth lines (`logs/auth`).

    /var/log/journal/<machine-id>/*.journal    persistent storage
    /run/log/journal/...                       volatile storage; in the evidence only if /run was captured
    rotated and archived files (*.journal, *.journal~), a namespace's directories, a remote copy

Inventory what was supplied: each location, each file, the machine id, the namespaces and any forwarded copy; then read the journald configuration and its drop-ins (storage, retention, forwarding) from the evidence. A missing `/var/log/journal` shows only that this path was not found in what was examined. It does not show the historical storage policy, and it does not exclude journals that were deleted, mounted elsewhere, forwarded or not collected. State the boots and time range actually examined (`boots` in the answer).

`journal_export` runs `journalctl` with `--file` or `--directory` at the evidence path, and never at this machine's journal: quote the path it read. Run it as a job with `secret_output: true` and `write_text: true` to keep the native export (`-o json --all`, every field, byte for byte) in `$OUT/journal-native.jsonl`; that file is the lossless result. The answer's projection carries, for each entry: `cursor`, `realtime_us` and `monotonic_us` raw with the decoded UTC `time`, `boot_id`, `machine_id`, the source clocks where present, the identity fields (`pid`, `uid`, `comm`, `exe`, `unit`, `audit_session`, `syslog_identifier`, `transport`) and `native_line`; a field journalctl wrote as bytes is named by its length (`encoding: bytes`) and never turned into text, a string is cut at 1024 characters with its whole length in `truncated_fields`, and the native file holds every field whole. Pass `since` and `until` with their zone (`UTC` suffix or `@epoch`): a bare time is read in this machine's zone and is refused. A journal directory that holds links is refused too, because journalctl may follow them out of the evidence: pass each real file. An entry over 32 MiB is counted and located (`parse_errors.oversized_lines`) and is in the native file.

Shows: the entries journald wrote in the files supplied. Does not show: entries that were never written, were rotated away or were not collected; that the `MESSAGE` is true; who ran a command whose `_CMDLINE` it carries. Record: locations, machine id, namespaces, `boots`, the path `journal_export` read, `cursor` and `native_line` of each cited entry.

Sensitive output: journal messages and `_CMDLINE` can hold passwords and tokens. The answer carries their length only; `write_text: true` and `preview_text: true`, each only in a job run with `secret_output: true`, give the text. Cite the cursor and `native_line`, never the text or a hash of it.
