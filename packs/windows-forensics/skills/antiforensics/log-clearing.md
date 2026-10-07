---
id: antiforensics/log-clearing
title: Cleared logs and missing snapshots
when: A log is empty or absent, shows a clearing record, or shadow copies are missing.
needs: [antiforensics/traces]
tools: [evtx_query, evtx_carve, regkv, vss_stores]
requires_host: []
---

Use when a log is empty, absent or carries a clearing record, or shadow copies are missing. Not for recovering the records (`logs/recovery`).

- A clearing event (Security 1102, System 104, each qualified by its provider) naming a subject account is evidence to interpret: report what it recorded (subject fields, time), not the content that was removed.
- An empty channel does not separate clearing from the other explanations (`logs/coverage`). Separate them with the channel's configuration (enabled state, size and retention in the SOFTWARE and SYSTEM hives, read with `regkv`; confirm the key names on this build), the file's own times and size, and `evtx_query`'s counts: `records_examined`, `events_matched`, `parse_errors`, `chunks_read` against `chunks_declared`. The tool gives no first or last record time: read the first and last `timestamp` in `result_file`; `highest_record_id_read` against `next_record_number_declared` says whether the reader reached the end of the file.
- A gap in `EventRecordID` within one file means records are absent from that file; it is not a count of events (`logs/coverage`).
- Then recover: records carved from unallocated space, a pagefile or a shadow copy (`evtx_carve`, `logs/recovery`).
- Snapshots: `vss_stores` listing no stores first needs a failed enumeration told from a clean zero. `status: failed` (exit 1) with `exit_code`, the whole output in `stdout_file` and `stderr_file`, and `stores_claimed` against `store_count` are the evidence; a run that exited 0 and reported zero stores found none at this volume offset, which is not proof that none existed. The states a snapshot can show are in `filesystem/shadowcopies`.
- A command line that deletes snapshots (`vssadmin`, WMI or PowerShell equivalents) in process-creation events or PowerShell logging shows an attempted operation, not that it succeeded: look for the outcome in the surviving stores and the service and provider events, where logged. Recognise such a command by what it does.

Shows: that a clearing, or a missing store, was recorded or found at this volume and offset. Does not show: what was lost, who did it, or that nothing else was altered. Record: the clearing record's subject and time, file times and counts, the interval the file covers, the vss_stores status and exit code.

Sensitive output: run `evtx_query` and `evtx_carve` as jobs (`secret_output: true`); `regkv` withholds by name or place only.
