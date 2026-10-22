---
id: logs/unified
title: The unified log
when: Examine retained diagnostic and operational events with their decoding and coverage limits.
needs: []
tools: [unified_log]
requires_host: []
---

Use when you search the unified log (`unified_log`) for events and must say what the archive covers. Not for which reader runs, its staging and its limits (`logs/unified-readers`, only if the run fails, is partial or the reader is in question).

Read the unified log beside the other retained sources: text logs still written, install and update records, application logs, and any audit or endpoint telemetry collected. It does not record everything that ran or every sign-in.

    /private/var/db/diagnostics/            .tracev3 files: Persist and the other log classes
    /private/var/db/diagnostics/timesync/   the clock relation for continuous time
    /private/var/db/uuidtext/               the format strings entries refer to

Keep the structure as acquired and record what is missing. A trace record can carry its own payload, so a missing `uuidtext` does not make every record unusable; it can leave some messages unrendered, so say which. The answer's `decoded_coverage.support_files` is a census by name of what the input holds, not a verdict that it is enough.

**Time and boots.** Keep the boot identity and the timesync data that relate continuous time to wall time, keep source timestamps and offsets, and write down how you converted to UTC. Investigate a clock discontinuity; do not join records from different boots on a counter.

**Reading the answer.** `status` is about the run: `failed` (a reader that exits 0 and writes nothing is this), `partial` (the reader failed, overran its time or was stopped, lines did not parse, or the output holds no entry, `reader_outcome: empty`; what was written is kept and counted) or `complete`. Complete is not a coverage claim. Read `status_basis`, `decoded_coverage`, `problems`, `warnings` and the stderr file. Keep the full output before you filter it.

**Using it.** Test narrow questions on process, subsystem, category and message: privacy-permission decisions, authentication, mounts, network changes and lock or unlock are candidates. Not every process launch, `sudo` call or authentication attempt is there.

**Coverage statement.** Name the acquired files, the boot or session, the subsystems searched, the interval observed, gaps, privacy losses and parser failures, and cite the whole output with a record locator (file and line) and the query. The earliest and the latest timestamp are outer bounds, not proof that everything between them was recorded. Retention depends on volume.

**Sensitive output.** Messages can carry command lines, paths, account and host names and sometimes a secret. The inline `entries` are a sample and pass the shared boundary by field type (a token-shaped run or the value after a secret's name is withheld, `PWD=` of a sudo line included); the reader's whole output named in `output` is not judged and holds every message as decoded. A `predicate` on message text counts what the preview withholds. Run broad extraction as a job with `secret_output: true` when messages may hold a secret; never write one into the ledger.

**Does not show.** That an event that is not in the log did not happen, who did it, or that the retained interval is the whole interval.
