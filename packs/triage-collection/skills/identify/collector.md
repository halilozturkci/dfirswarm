---
id: identify/collector
title: Naming the collector and what its records say
when: A delivery is a tree or an archive from a collector.
needs: []
tools: [collection_id, collection_manifest_parse, archive_extract]
requires_host: []
---

Use when a delivery is a tree or an archive of copied files. Not for a disk image (`evidence/imaging`) or for its limits (`gaps/what-is-missing`).

1. Run `collection_id` on the directory. An archive is not opened by this tool: the `collection-intake` recipe reads a zip or tar and its records, extracting nothing, and `archive_extract` extracts (`normalise/container-members`). `collection_manifest_parse` reads the records (`identify/collector-records`). The answer is a hypothesis from names, first bytes and limited log parsing, not an audit: read the original configuration, manifests and logs before you accept its attribution or failure count.
2. Keep three states apart. Attribution: `collector_candidates`, each with the paths it saw (several collectors and several runs can be present; a top-level `C` directory is a layout clue and names no collector). Acquisition mode: what the collector read, which no file name shows. Composition: `delivery.kind`, `mixed` meaning more than one kind of object (copied files below the top level, disk container, memory capture, archive, or `unknown`: a name that says image with no signature), each classified in `objects` with its `basis`. A note beside an image is another file, not a second kind.
3. Read each log's `status`: `parsed` means every row or line matched an adapter. `failed_target_count` is a number only when every failure-source log was read whole, the walk was complete and no archive went unopened; `null` means not determined, never zero, and `failed_targets_seen` is the rows read all the same. A zero is "none in the rows read", not "it finished". Read a UAC record's `unlabelled_examples` by hand.
4. **The collector's log is evidence.** Keep every recorded skip or error with its locator and its own words, and do not explain it: a lock, a permission boundary, an absent path, an unsupported object and a defect look alike. A recorded failure does not make a target suspicious. Outcome states: `verify/target-outcomes`.
5. **The profile is intended scope.** Record its exact version or supplied definition, parameters, exclusions, source roots, privileges and any time or size filter, and reconcile it with attempts, failures and delivered objects. A missing target can stop a direct examination without ruling out traces in other supplied sources: state the limit per question.

Only if you must describe a family's usual layout, or the tool names no collector: `identify/collector-clues`. Only if the collector read a live host, a mounted image or a snapshot and time or contamination matters: `identify/acquisition-mode`.

Shows: which records are present, what they say they did, and what the delivery is made of. Does not show: that the collector finished, what it was asked to copy, that a log is complete, or that no manifest exists where none was found.
Record: the tool answer, each log path and status, the profile you were given.
Sensitive output: logs can hold command lines and paths; run `collection_id` as a job with `secret_output: true`, cite locators, never copy a credential-shaped string or its hash. Withholding is by shape: a secret of another shape is printed.
