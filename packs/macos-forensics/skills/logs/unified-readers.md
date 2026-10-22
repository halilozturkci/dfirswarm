---
id: logs/unified-readers
title: Unified log readers, staging and retention levels
when: unified_log fails or is partial, or the choice of reader or its version is in question.
needs: []
tools: [unified_log]
requires_host: [unifiedlog_iterator, log]
---

Use only if `unified_log` fails or is partial, or you must say which reader decoded the archive. Not for the coverage statement or the answer's fields (`logs/unified`).

**Readers.**

    log show --archive <path> --style ndjson --info --debug     Apple's reader, on a Mac
    unifiedlog_iterator                                         the declared reader elsewhere

`unified_log` runs whichever it finds. On Linux that is Mandiant's `unifiedlog_iterator` (pinned in this pack's requires; its version is recorded in `reader`); the whole decoded output is kept as JSONL beside its stderr. A directory holding both `diagnostics` and `uuidtext` is staged as one archive under the output directory (counted, bounded, and refused if it holds a link or a member present in both trees with different bytes). `predicate`, `start` and `end` are refused there: search the whole JSONL afterwards and keep the query. `timeout_seconds` (900 by default, at most 1100) covers the staging, the census and the reader: the reader gets what is left (`budget` says how it was spent), and a stop signal ends it. On macOS the tool runs Apple's `log` with `--archive`, which wants a valid `.logarchive`; the staging is Linux's, so a copied `diagnostics` tree is not the same input. Use the declared reader. Any other (the archived Python UnifiedLogReader among them) has its own supported versions: check them against the version the evidence carries before you rely on its output.

`--info --debug` includes the entries retained at those levels. It does not bring back an entry that was never persisted, was removed by retention or was redacted: keep `<private>` and unresolved values as limits. Give time boundaries an explicit offset and note the reader's output zone.

Shows: the entries the named reader and version decoded from the staged archive. Does not show: entries never persisted, removed by retention or redacted, or that another reader would decode the same.
Record: the reader and its version (`reader`), the staged input, the query run on the JSONL, the output zone.
