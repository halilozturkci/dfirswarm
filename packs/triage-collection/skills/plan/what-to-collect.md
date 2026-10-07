---
id: plan/what-to-collect
title: Requesting additional evidence through the operator
when: A material question needs evidence that the delivery does not contain.
needs: []
tools: [collection_id, collection_index]
requires_host: []
---

Use when a missing source could settle a question. Not for running a collector: the harness examines supplied evidence and never performs live collection.

1. Start from what you hold: `collection_id` (`failed_targets`, `not_observed`) and `collection_index` (the census) show it. Ask only for what neither lists. Do not launch a collector against the source host, the analysis VM or anything else, and do not connect to an endpoint. You write a request; the operator decides whether anything is collected.
2. A request names the missing source, who holds it, the question it could settle, how urgent it is (volatile: it may be lost) and what authority collecting it needs. Send it as the acquisition ask the worker prompt describes: close the lead `needs_operator` with `ask.kind` acquisition and `source`, `where`, `expected_value`, `urgency` and `authority_needed`. Where the case admits no more evidence, record that constraint and its effect on the answer as a limitation: it is never a finding that the source is absent.
3. **Order is the examiner's call, not a rule.** For a delivered collection or a dead disk, write down the historical acquisition order and what it lost; an examination cannot recreate volatile state that was not preserved, and an evidential disk is not booted to approximate it. If the operator can authorise acquisition from a running source, say which evidence is most at risk and what collecting it changes. RAM, process and connection state, short-retention logs and records held elsewhere lose value at different times; memory is often urgent. The authorised examiner chooses and records the order, the trade-offs and the changes the collection itself causes.
4. Ask for the collector's own record: its logs, manifests, the configuration it used and the acquisition record.
5. Ask for the time on the machine against a trusted reference, with both zones, the measurement uncertainty and any evidence of synchronisation or clock changes. One comparison is not a constant historical offset; logs already held may bound it.
6. Ask for configuration beside the logs. A configuration is observed state: it is not a change, or its author, unless a comparison or change record shows when and how.
7. Key files, verifier stores and saved credentials only where the question and the authority justify it, read in jobs with `secret_output: true`. Report location, kind and meaning; never values, fragments or hashes of secrets.

Only if the delivery is Windows: `plan/sources-windows`. Only if it is Linux or Unix-like: `plan/sources-linux`.

Record: each request as above, the question it serves, and the limitation you recorded if it was declined.
