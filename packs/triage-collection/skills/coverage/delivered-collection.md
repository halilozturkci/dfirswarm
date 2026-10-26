---
id: coverage/delivered-collection
title: From delivered objects to question coverage
when: You must say what a delivery covers for a question, before a negative or a count of "all".
needs: [evidence/coverage]
tools: [collection_coverage, collection_manifest_verify]
requires_host: []
---

Use when one question depends on what a collection holds and what its collector says it took. Not for how a search is worded (`evidence/coverage`) or writing the bound into the report (`gaps/coverage-statement`).

1. Write the question as patterns first: the artefact's path on the source (`source_paths`, such as `*/config/system`) and, if you know the collector's layout, its delivered path (`delivered_paths`). A pattern is a case-insensitive glob (`*`, `?`, either separator), not a regular expression.
2. Run `collection_coverage` with `questions`. Add `requested` (the targets the profile asked for, as you read them there, never guessed), `examined` (the delivered paths you have read) and, when integrity matters, `verification` (the `checks` table of `collection_manifest_verify`): without it integrity is not assessed.
3. Read each question's counts as separate statements: *delivered*; *recorded as copied or uploaded and absent* (only from a complete census); *recorded as skipped or failed*, in the collector's words (quote by locator; no cause); *delivered without a record* (only where a per-file record covers the directory); *no file and no record* (`no_file_and_no_record`, only from a complete census). With an incomplete census (a directory not listed, the walk stopped) the state is `census_incomplete`; the statement names what was not examined and states no absence. "Not delivered", "not examined", "failed to parse" and "searched without a match" are four statements.
4. A record not read whole (`sources[].status` not `parsed`, or a KAPE run with no skip log) leaves the absence of a skip row unknown: the state is `no_file_and_no_record_read`, not `no_file_and_no_record`, and the statement names it. Never read it as "the collector took it".
5. A `requested` pattern is `delivered`, `recorded_not_delivered`, `recorded_delivery_not_decided`, `recorded_as_skipped_or_failed`, `unknown_census_incomplete`, `unknown_records_unread` or `neither_delivered_nor_recorded`. Only the last is an acquisition question (`plan/what-to-collect`), not a finding about the source, and only a complete census and records read whole reach it; an `unknown_*` or undecided state is a gap to close, not a result.
6. Use the generated statement as written and add scope (hosts, users, time range, tools) only from supplied records. No sentence that something was never present comes from this tool or belongs in the report.

Shows: what a delivery holds for a question and what the collector's records say of the same targets. Does not show: that the source never held the artefact, what the collector was asked to take (unless `requested` says), or that a skip row would have been written.
Record: the question, patterns, counts, statement, `sources` statuses, and the `kind=coverage` entry that cites them (`detection_opportunity`, `acquisition_ask` or `acquisition_none_why`).
Sensitive output: run `collection_coverage` as a job with `secret_output: true`; quote a collector's reason by locator, never a credential-shaped string. Withholding is by shape: a secret of another shape is printed.
