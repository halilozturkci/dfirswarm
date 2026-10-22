---
id: identify/collector-records
title: What a collector's records say
when: You rely on a collector's own copy, skip, upload or log records.
needs: []
tools: [collection_manifest_parse, collection_manifest_verify]
requires_host: []
mentions: [CyLR]
---

Use when you read what a collector says it did. Not for naming the collector from a layout (`identify/collector`, `identify/collector-clues`).

Run `collection_manifest_parse`: one canonical record per row or line, the raw row's locator, and each adapter's schema in `adapters`. A record whose shape no adapter knows is `partial` or `unsupported`; `failures_recorded.count` is then `null`, which is not zero. The collector's version is `unknown` unless a record states it. What each family leaves, and what to take from it:

- **KAPE.** Per run: `*_CopyLog.csv` (source, destination, size, SHA-1 of the source, the file's own times, the copy time), `*_SkipLog.csv` (source and the collector's reason) and `*_ConsoleLog.txt`. A copy row is a claim that a file was copied; its SHA-1 column is named for the source file. A deferred copy and a skip are the collector's outcomes. Keep each run apart. Which targets were configured is not in these records.
- **Velociraptor** (the container version this pack was checked against; the adapter's schema names it). `uploads.json` rows say where an upload was stored (`vfs_path`), its logical size and its stored size; a failed upload is not there but in the result rows (`results/*.json`, an upload record with `Error`) and in `log.json`. An upload smaller than its file is sparse or partial: its digest is of another byte sequence than the stored one. Read the artefact result tables as derived output, apart from the uploaded bytes.
- **UAC** (the log level words differ between releases; both forms are read). `uac.log` lines with an ERR level are errors; a summary that says 0 errors is not one, and a line that fits no shape is kept unlabelled. A `hash_executables` list is a claim about files of the source host; whether a collected copy of one is in `[root]` is for the join (`collection_manifest_verify`) to say. Bodyfile and live-response output are command output, not copies.
- **CyLR.** No record is read: a mirrored tree is compatible with it and with a hand copy. Say so; do not invent a profile or a manifest.
- **Cado and others.** Name the product and export type, read what it supplied, and assert no layout this pack has not seen.

Whatever the family, three questions stay open until a record answers them: what the collector was asked to take, whether it finished, and what its records omit.

Shows: what the collector recorded, in its words and on its clock. Does not show: that it is true, that it is complete, or what it was configured to take.
Record: each adapter and its status, the version and its basis (or `unknown`), and every record you rely on by locator.
Sensitive output: run `collection_manifest_parse` as a job with `secret_output: true`; a record can hold a command line or a path with a secret, and a digest of a credential store is withheld. Withholding is by shape: a secret of another shape is printed.
