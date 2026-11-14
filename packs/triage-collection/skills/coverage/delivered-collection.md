---
id: coverage/delivered-collection
title: From delivered objects to question coverage
when: You must say what a delivery covers for a question, before a negative or a count of "all".
needs: [evidence/coverage]
card: collection_coverage {"root": "<collection dir>", "questions": [{"id": "q1", "source_paths": ["<glob>"]}]}: patterns are globs, not regexes. census_incomplete, no_file_and_no_record_read and unknown_* states assert no absence: they are gaps. Without verification, integrity is not assessed. Run it as a job with secret_output: true. Does not show: that the source never held the artefact.
tools: [collection_coverage, collection_manifest_verify]
requires_host: []
mentions: [KAPE]
---

Use when a question depends on what a collection holds and what its collector says it took. Not for wording a search (`evidence/coverage`) or the report's bound (`gaps/coverage-statement`).

1. Write patterns: the source path (`source_paths`, e.g. `*/config/system`) and, if you know the layout, the delivered path (`delivered_paths`): case-insensitive globs (`*`, `?`, either separator), not regular expressions.
2. Give `collection_coverage` `questions`, `requested` (the profile's targets as you read them, never guessed), `examined` (delivered paths you read) and, for integrity, `verification` (`collection_manifest_verify`'s `checks` table; without it integrity is not assessed).
3. Each count is its own statement: *delivered*; *recorded as copied or uploaded and absent* (only from a complete census); *recorded as skipped or failed*, in the collector's words (by locator, no cause); *delivered without a record* (only where a per-file record covers the directory); `no_file_and_no_record` (only from a complete census). An incomplete census (a directory not listed, the walk stopped) is `census_incomplete`, naming what was not examined and stating no absence. "Not delivered", "not examined", "failed to parse" and "searched without a match" are four statements.
4. A record not read whole (`sources[].status` not `parsed`, or a KAPE run with no skip log) leaves a missing skip row unknown: `no_file_and_no_record_read`, not `no_file_and_no_record`. It never means "the collector took it".
5. A `requested` pattern is `delivered`, `recorded_not_delivered`, `recorded_delivery_not_decided`, `recorded_as_skipped_or_failed`, `unknown_census_incomplete`, `unknown_records_unread` or `neither_delivered_nor_recorded`. Only the last (a complete census, records read whole) is an acquisition question (`plan/what-to-collect`), not a finding about the source; an `unknown_*` or undecided state is a gap to close.
6. Use the generated statement as written; add scope only from supplied records. No "never present" comes from this tool or belongs in the report.

Shows: what a delivery holds and what the collector's records say, per question. Does not show: that the source never held the artefact, what the collector was asked to take (unless `requested` says), or that a skip row would have been written.
Record: the question, patterns, counts, statement, `sources` statuses, and the `kind=coverage` entry citing them (`detection_opportunity`, `acquisition_ask` or `acquisition_none_why`).
Sensitive output: run `collection_coverage` as a job with `secret_output: true`; quote a reason by locator, never a credential-shaped string. Withholding is by shape: another shape is printed.
