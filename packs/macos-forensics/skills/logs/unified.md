---
id: logs/unified
title: The unified log
when: Examine retained diagnostic and operational events with their decoding and coverage limits.
needs: [triage/system-profile]
tools: [unified_log]
requires_host: [unifiedlog_iterator, log]
---

Read the unified log beside the other retained sources: text logs that are still
written, install and update records, application logs, and any audit or endpoint
telemetry that was collected. It is not a complete record of what ran or who
authenticated.

    /private/var/db/diagnostics/            .tracev3 files: Persist and the other log classes
    /private/var/db/diagnostics/timesync/   the clock relation for continuous time
    /private/var/db/uuidtext/               the format strings entries refer to

Keep the whole structure as acquired and record what is missing. A trace record can
carry its own payload as well as references, so a missing `uuidtext` does not make every
record unusable; it can leave some messages unrendered, so say which. The answer's
`decoded_coverage.support_files` is a census by name of what the input holds, not a
verdict that it is enough.

**Time and boots.** Keep the boot identity and the timesync data that relate continuous
time to wall time, keep source timestamps and offsets, and write down how you converted
to UTC. Investigate a clock discontinuity. Do not join records from different boots on a
counter.

**Readers.**

    log show --archive <path> --style ndjson --info --debug     Apple's reader, on a Mac
    unifiedlog_iterator                                         the declared reader elsewhere

`unified_log` runs whichever it finds. On Linux that is Mandiant's `unifiedlog_iterator`
(pinned in this pack's requires; its version is recorded in `reader`); the whole decoded
output is kept as JSONL beside its stderr. A directory holding both `diagnostics` and
`uuidtext` is staged as one archive under the output directory (counted, bounded, and
refused if it holds a link or a member present in both trees with different bytes).
`predicate`, `start` and `end` are refused there: search the whole JSONL afterwards and
keep the query. On macOS the tool runs Apple's `log` with `--archive`, which wants a
valid `.logarchive`; the staging is Linux's, so a copied `diagnostics` tree is not the
same input. Use the declared reader. Any other (the archived Python UnifiedLogReader
among them) has its own supported versions: check them against the version the evidence
carries before you rely on its output.

`--info --debug` includes the entries retained at those levels. It does not bring back
an entry that was never persisted, was removed by retention or was redacted:
keep `<private>` and unresolved values as limits. Give time boundaries an explicit
offset and note the reader's output zone.

**Reading the answer.** `status` is about the run: `failed` (a reader that exits 0 and
writes nothing is this), `empty`, `partial` (the reader failed or overran its time, or
lines did not parse; what was written is kept and counted) or `complete`. Complete is
not a coverage claim. Read `decoded_coverage` (lines, JSON records, entries, lines that
are not records, records with none of an entry's fields), `problems`, `warnings` and the
stderr file. Keep the full output before you filter it.

**Using it.** Test narrow questions on process, subsystem, category and message:
privacy-permission decisions, authentication, mounts, network changes and lock or unlock
are candidates. Do not assume every process launch, argument, `sudo` call or
authentication attempt is there.

**Coverage statement.** Name the acquired files, the boot or session, the subsystems
searched, the observed interval, gaps, privacy losses and parser failures, and cite the
whole output with a record locator (file and line) and the query. The earliest and the
latest timestamp are outer bounds, not proof that everything between them was recorded.
Retention depends on volume and policy.

**Sensitive output.** Messages can carry command lines, paths, account and host names and
the occasional secret. The inline `entries` are a sample; run broad extraction as a job,
and never write a secret from a message into the ledger (the worker rules).

**Does not show.** That an event that is not in the log did not happen, who did it, or that
the retained interval is the whole interval.
