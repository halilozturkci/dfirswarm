---
id: artifacts/fsevents
title: FSEvents, retained filesystem change records
when: Assess filesystem changes and relative order without inventing timestamps.
needs: []
card: fsevents_parse reads 1SLD and 2SLD pages only; another version is unsupported and the rest of that file is not decoded. Read status_basis, files_by_state and problems first: a zero count or an exit of 0 is not a finished examination. Past max_seconds the rest is not_attempted. A negative is: no matching record decoded from these files, by this parser and filter. Does not show: when a change happened, who made it, or that an absent path was never touched.
tools: [fsevents_parse]
requires_host: []
---

Use when you read `.fseventsd` records for what changed. Not for ordering or dating a record, flags or an external volume's log (`artifacts/fsevents-dating`, only if the question needs the order or a date).

Find `.fseventsd` in each acquired volume's root, the Data volume included; keep its record files and `fseventsd-uuid` (the log's, not the APFS volume UUID). A merged tree can hide a directory's volume.

    /.fseventsd/fseventsd-uuid    the log's identity
    /.fseventsd/<16 hex digits>   gzip record files

FSEvents is a change-notification history, not an audit: what survives depends on retention, exclusions, coalescing, collection and damage or restoration. Do not assume a complete log, or a record for every operation.

**Check what the parser read before you rely on it.** `fsevents_parse` reads `1SLD` and `2SLD` pages. A page of another version (`3SLD`, say) is `unsupported` and the rest of that file is not decoded, as is a non-record file; `status` is `failed` when no file was read. Read `status_basis`, `files_by_state`, `coverage` and `problems`. A zero count, an empty `problems` list or an exit of 0 is not a finished examination: for a format the tool does not read, use a validated parser or record it as not examined. Past its clock (`max_seconds`, 200) or on a stop signal the file in hand is partial where `problems` says and the rest are `not_attempted`; read them one at a time. `problem_occurrences` counts problems, `problems_total` rows (later ones are `folded`).

For a record that matters keep the file, format version, event id, raw and decoded flags, path, node id (version 2) and the offsets the tool prints. A flag bit the tool has no name for is `flags_undecoded`. The flag names are the on-disk map, not the public API constants.

**Does not show.** When a change happened, who made it, what it contained, or that a path absent from the log was never touched. A negative reads: "no matching record was decoded from these files, by this parser and filter", with the formats supported, the failures counted and the retention limits stated.

**Sensitive output.** A path can hold an identifier or a token. A token-shaped path component is shown as `<withheld N characters: reason>` (`status` is `partial` when the backstop replaced one); a plain password, a BitLocker key or an ordinary-looking name is printed. `contains` (a restricted regular expression) matches the path as printed, so a piece of a withheld name matches nothing; `contains_blind_records` counts records it could not see into. Read names that matter in a job with `secret_output: true`; `write_values` there writes the originals to a private file under `$OUT`. Cite the record, never a withheld name.
