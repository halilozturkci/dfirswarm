---
id: ios/unified-logs
title: iOS unified logs on Linux
when: The question depends on an iOS subsystem's diagnostic or operational log.
needs: [ios/artifacts]
tools: [unified_log]
requires_host: [UnifiedLogReader.py]
---

An iOS full-file-system extraction can hold the same unified-log pieces as
macOS: `Persist/*.tracev3`, UUID text and timesync data. They belong together;
a trace file without its UUIDText data can leave format strings unresolved,
and without timesync the continuous clock cannot be placed safely on UTC.

Use the `unified_log` pack tool on the directory that contains those pieces.
It stages the expected layout for `UnifiedLogReader.py` and keeps the reader's
stdout, stderr and generated files. Search that retained output; do not pipe
the only copy through `grep`.

Absence is narrow. State the trace files, time range, subsystem/category or
search expression, reader version, unresolved-format count and parse errors.
A missing rendered message may be missing UUID text, not a missing event.
