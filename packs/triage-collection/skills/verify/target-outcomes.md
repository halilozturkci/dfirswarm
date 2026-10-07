---
id: verify/target-outcomes
title: What a collector did and did not copy, target by target
when: A skip, error or result log exists.
needs: []
tools: [collection_id]
requires_host: []
---

Use when you read a collector's own account of its targets. Not for choosing what to ask for (`plan/what-to-collect`).

1. A skip log is not the whole failure universe. Reconcile the effective target definitions with every record supplied: copy, skip, error, console, result and transfer logs. `collection_id` reads the KAPE logs, UAC's log lines and Velociraptor's index; where an adapter says `partial` or `unsupported` the count is incomplete, and a log it does not read is read by hand.
2. Sort every target into one state, and keep the collector's own reason: intentionally excluded; condition not met; not attempted; attempted and failed; collected but not delivered; delivered but unreadable. Where the records cannot tell two states apart, write unknown. Do not pick the likelier.
3. A row in `failed_targets` is a recorded outcome (`skipped` or `error`) with its locator. It is the collector's meaning of the word, not this tool's, and not a cause: a lock, a permission boundary, an absent path, an unsupported object and a defect look alike.
4. Missing error records do not establish a successful collection. A target with no row anywhere is not delivered and not examined, not "fine".
5. A failure is a fact about the collection. It is not proof that the target mattered, or that anyone interfered with it.

Shows: what the collector says happened to each target. Does not show: why, whether the collector's list was complete, or whether the target existed on the source.
Record: per target its state, the record and locator, the collector's wording, and the questions the loss limits.
