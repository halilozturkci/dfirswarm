---
id: identify/collector
title: Naming the collector and what its records say
when: A delivery is a tree or an archive from a collector.
needs: []
card: collection_id {"root": "<collection dir>"}: a hypothesis from names, first bytes and some log parsing, not an audit. failed_target_count null is not determined, never zero; a zero is "none in the rows read", not "it finished". Does not show: that the collector finished, or what it was asked to copy.
tools: [collection_id, collection_manifest_parse, archive_extract]
requires_host: []
---

Use when a delivery is a tree or archive of copied files. Not for a disk image (`evidence/imaging`) or its limits (`gaps/what-is-missing`).

1. Run `collection_id` on the directory; it opens no archive (the `collection-intake` recipe reads a zip or tar and its records without extracting; `archive_extract` extracts: `normalise/container-members`; `collection_manifest_parse` reads records: `identify/collector-records`). The answer is a hypothesis from names, first bytes and limited log parsing, not an audit: check its attribution and failure count against the original configuration, manifests and logs.
2. Keep three states apart. Attribution: `collector_candidates`, each with its paths (several collectors and runs can be present; a top-level `C` names none). Acquisition mode: what it read; no file name shows it. Composition: `delivery.kind` (`mixed`: more than one kind of object: copied files below the top level, disk container, memory capture, archive, or `unknown`, a name saying image with no signature), each object classified in `objects` with its `basis`; a note beside an image is no second kind.
3. A log's `status` `parsed` means every row or line matched an adapter. `failed_target_count` is a number only when every failure-source log was read whole, the walk completed and no archive stayed unopened; `null` means not determined, never zero (`failed_targets_seen` still lists the rows read). A zero is "none in the rows read", not "it finished". Read a UAC record's `unlabelled_examples` by hand.
4. **The collector's log is evidence.** Keep every recorded skip or error with its locator and words, unexplained: a lock, a permission boundary, an absent path, an unsupported object and a defect look alike. A failure does not make a target suspicious. Outcome states: `verify/target-outcomes`.
5. **The profile is intended scope.** Record its exact version or supplied definition, parameters, exclusions, source roots, privileges and any time or size filter, and reconcile it with attempts, failures and deliveries. A missing target stops a direct examination, not traces in other supplied sources: state the limit per question.

Only if you describe a family's layout, or no collector is named: `identify/collector-clues`. Only if time or contamination of a live, mounted or snapshot read matters: `identify/acquisition-mode`.

Shows: which records are present, what they say was done, and what the delivery is made of. Does not show: that the collector finished, what it was asked to copy, that a log is complete, or that no manifest exists.
Record: the answer, each log path and status, the profile given.
Sensitive output: logs hold command lines; run `collection_id` as a job with `secret_output: true`, cite locators, never copy a credential-shaped string or its hash. Withholding is by shape: another shape is printed.
