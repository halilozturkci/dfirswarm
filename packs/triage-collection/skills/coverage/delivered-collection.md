---
id: coverage/delivered-collection
title: From delivered objects to question coverage
when: You must say what a delivery covers for a question, before a negative or a count of "all".
needs: [evidence/coverage]
tools: [collection_coverage, collection_manifest_verify]
requires_host: []
---

Use when one question depends on what a collection holds and on what its collector says it took. Not for how a search is defined and worded (`evidence/coverage`) or for writing the bound into the report (`gaps/coverage-statement`).

1. Write the question as patterns first: the artefact's path on the source (`source_paths`, such as `*/config/system`) and, if you know how the collector lays a tree out, its delivered path (`delivered_paths`). A pattern is a case-insensitive glob (`*`, `?`, either separator), not a regular expression, and it matches a path as the collector wrote it.
2. Run `collection_coverage` with `questions`. Add `requested` (the targets the collector's profile was asked to take, as you read them in the profile, never guessed), `examined` (the delivered paths you have read) and, when integrity matters, `verification` (the `checks` table of `collection_manifest_verify`). Without `verification` the statement says integrity was not assessed.
3. Read each question's counts as separate statements: *delivered* (files that match); *recorded as copied or uploaded and absent from a complete census*; *recorded as skipped or failed*, in the collector's own words (quote by locator, give no cause); *delivered without a record* (meaningful only where the directory has a per-file record); *neither delivered nor recorded*. "Not delivered", "not examined", "failed to parse" and "searched without a match" are four statements; each needs its own record.
4. A collector record that was not read whole (`sources[].status` not `parsed`, or a KAPE run with no skip log) leaves the absence of a skip row unknown. The statement names it; do not turn it into "the collector took it".
5. A `requested` pattern that is neither delivered nor recorded is an acquisition question (`plan/what-to-collect`), not a finding about the source.
6. Use the generated statement as written and add scope (hosts, users, time range, tools) only from supplied records. No sentence that something was never present comes from this tool, and none belongs in the report.

Shows: what a delivery holds for a question and what the collector's records say about the same targets. Does not show: that the source never held the artefact, what the collector was asked to take (unless `requested` says), or that a skip row would have been written.
Record: the question, its patterns, the counts and the statement, the `sources` statuses, and the `kind=coverage` entry that cites them (`detection_opportunity`, `acquisition_ask` or `acquisition_none_why`).
Sensitive output: run `collection_coverage` as a job with `secret_output: true`; quote a collector's reason by locator, never a credential-shaped string. Withholding is by shape: a secret of another shape is printed.
