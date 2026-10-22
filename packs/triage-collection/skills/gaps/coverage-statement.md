---
id: gaps/coverage-statement
title: The coverage statement for one question
when: An answer is a negative or a completeness claim.
needs: []
tools: [collection_id, collection_coverage]
requires_host: []
---

Use when you bound one answer. Not for classifying what the delivery holds (`gaps/what-is-missing`).

1. Build the statement per material question from the delivered inventory and your own examination record (`coverage/delivered-collection` makes the matrix with `collection_coverage`). Keep three scopes apart: what the collector meant to take (intended), what reached you (delivered, from `collection_id` and the census) and what you read (examined).
2. Name the objects, hosts or users, the retained time range, the tools and their settings. Say what was skipped or failed (`failed_targets`, each with its locator) and whether the event you ask about would have left a trace in these sources: that is the `detection_opportunity` of the `kind=coverage` entry the worker prompt asks for before a negative.
3. Mark the areas allocated, deleted, unallocated, slack and secondary as searched, skipped or `not_applicable`, with the reason. Keep the four statements of `coverage/delivered-collection` apart: not delivered, not examined, failed to parse, searched without a match.
4. Fill the template only from cited records: "The supplied evidence comprises [objects and acquisition modes]. For [question] we examined [objects, identities, time range and method]. [Sources or regions] were unavailable or not examined because [documented reasons]. [Observed result] is limited to that scope; [remaining proposition] is not determinable from this delivery."
5. A bounded negative holds only for the completed search it describes. Where a missing source could settle the question, open the acquisition ask (`plan/what-to-collect`) and name it in the coverage entry (`acquisition_ask`), or say why none would settle it (`acquisition_none_why`); when the case admits no more evidence, open no ask and name that policy in `acquisition_none_why`.
6. Never infer the cause of a failed copy. A collector's recorded reason is quoted, not extended.

Shows: what the answer rests on and where it stops. Does not show: that the event did not happen, or that an unexamined source is empty.
Record: the `kind=coverage` entry (value, refs, time range, search method, settings, coverage_actual, skipped and failures, areas, detection_opportunity, looked_for or looked_for_none_why, result_refs, alternatives), then the answer that cites it.
Sensitive output: run `collection_id` as a job with `secret_output: true`; quote a collector's reason by locator, never a credential-shaped string.
