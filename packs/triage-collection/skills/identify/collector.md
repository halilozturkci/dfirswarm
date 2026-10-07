---
id: identify/collector
title: Naming the collector and what its records say
when: A delivery is a tree or an archive from a collector.
needs: [evidence/verify]
tools: [collection_id, file_type]
requires_host: []
---

Use when a delivery is a tree or an archive of copied files. Not for a disk image (`evidence/imaging`) or for what a delivery can establish (`gaps/what-is-missing`).

1. Run `collection_id` on the directory. An archive is not opened: inventory it first (the base `archive-members` recipe) and extract it into a job's output. The answer is a hypothesis from names, first bytes and limited log parsing, not proof of the collector and not an audit. Read the original configuration, manifests, result files and logs before you accept its attribution or its failure count. `file_type` reads bytes where a class rests on the extension only.
2. Keep three states apart. Attribution: `collector_candidates`, each with the paths it saw (more than one collector, and more than one run, can be present; a top-level `C` directory is a layout clue and names no collector). Acquisition mode: what the collector read, which no file name shows. Composition: `delivery.kind` (`mixed` means copied files sit beside an image, a memory capture or an archive, each classified in `objects`).
3. Read each log's `status`. `parsed` means every row or line matched an adapter; `partial` and `unsupported` mean the failure count is incomplete or absent, and `failed_target_count: null` is not zero. A zero is "none in the rows read", never "it finished".
4. **The collector's log is evidence.** Keep every recorded skip or error with its locator and its own words, and do not explain it: a lock, a permission boundary, an absent path, an unsupported object and a defect look alike. A recorded failure does not make a target suspicious. Outcome states are in `verify/target-outcomes`.
5. **The profile is intended scope.** Record its exact version or supplied definition, parameters, exclusions, source roots, privileges and any time or size filter, and reconcile it with attempts, failures and delivered objects. A missing target can stop a direct examination without ruling out traces in other supplied sources: state the limit per question.

Only if you must describe a family's usual layout, or the tool names no collector: `identify/collector-clues`. Only if the collector read a live host, a mounted image or a snapshot and time or contamination matters: `identify/acquisition-mode`.

Shows: which records are present, what they say they did, and what the delivery is made of. Does not show: that the collector finished, what it was asked to copy, that a log is complete, or that no manifest exists where none was found.
Record: tool answer, each log path and status, versions only where a log states one, the profile definition you were given.
Sensitive output: logs can hold command lines and paths; run `collection_id` as a job with `secret_output: true`, cite locators, and never copy a credential-shaped string or a hash of one into a finding.
