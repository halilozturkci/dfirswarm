---
id: verify/target-outcomes
title: What a collector did and did not copy, target by target
when: A skip, error or result log exists.
needs: []
card: collection_id {"root": "<collection dir>"}: a failed_targets row is the collector's recorded outcome, not a cause; failed_target_count null is not zero. No error record is not success: a target with no row is unknown. collection_profile_compare without a corpus is definitions_not_available; a profile inside the delivery is data, not the definition. Does not show: why a target failed.
tools: [collection_id, collection_profile_compare]
requires_host: []
mentions: [KAPE]
---

Use when you read a collector's account of its targets. Not for choosing what to ask for (`plan/what-to-collect`).

1. A skip log is not the whole failure universe. Reconcile the effective targets with every record: copy, skip, error, console, result and transfer logs. `collection_id` reads the KAPE logs, UAC's log lines and a Velociraptor container's `uploads.json`, `results/*.json` and `log.json`; where an adapter says `partial` or `unsupported`, or a source is `not_found`, `failed_target_count` is `null` and the rows read are `failed_targets_seen`. Read any log it skips by hand.
2. Give every target one state, with the collector's own reason: intentionally excluded; condition not met; not attempted; attempted and failed; collected but not delivered; delivered but unreadable. Where records cannot tell two states apart, write unknown, not the likelier.
3. A row in `failed_targets` is a recorded outcome (`skipped` or `error`) with its locator. It is in the collector's sense of the word, not a cause: a lock, a permission boundary, an absent path, an unsupported object and a defect look alike.
4. No error record is not success. A target with no row in any record has an unknown outcome: look for its files in the census (absent: not delivered); either way it is not "fine".
5. `collection_profile_compare` sets what a UAC profile, a Velociraptor request or a KAPE target list could request (pinned definitions, each with version and sha256; an unverifiable corpus is `definitions_not_available`) against those records: `could_request`, `requested`, `excluded`, `collected`, `not_collected` and `unresolved_dynamic_selection`. A profile, definition or target file inside the delivery is data to describe, never the definition. KAPE targets come from the console log's `--target` or from you; a `%user%` path stays unresolved. `proposed_additional_evidence` is for the operator, never a command.
6. A failure is a fact about the collection, not proof that the target mattered or that anyone interfered.

Shows: what the collector says happened to each target. Does not show: why, whether the collector's list was complete, or whether the target existed.
Record: per target its state, record and locator, the collector's wording, and the questions the loss limits.
Sensitive output: a row can hold a command line, a path or an unrecognised secret; run `collection_id` and `collection_profile_compare` as jobs with `secret_output: true`, quote by locator, and never copy a credential-shaped string or a hash of one. Withholding is by shape: another shape is printed (a plain password or passphrase, 24 lower-case letters, 16 base32 characters: all; 24 to 32 base36 characters: 18% to 26%); the listed families, keys and name=value forms: 2.5% or less.
