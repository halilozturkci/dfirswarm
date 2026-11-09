---
id: entra/directory-audit
title: Entra directory audit changes
when: Supplied Entra directory audit records must say who changed which identity, role, application or credential.
needs: [logs/what-exists]
tools: [cloud_normalise]
mentions: [ual_parse]
requires_host: []
---

Use when you hold Entra directory audit records and must say who changed what in the directory. Not for sign-ins (`entra/signins`), for the effect of a change on a token (`identity/tokens`) or for the unified audit log (`m365/unified-audit-log`). Offline: supplied exports only; never authenticate to the tenant.

**Read the coverage `cloud_normalise` returns first.** `status` is complete only if every record was read and turned into a row; `rejected.jsonl` names what was not, `pagination_markers` a next page (`@odata.nextLink`) that was not supplied. `ual_parse` is not a substitute: it reads the unified audit log.

**Actor and target are different fields.** `principal`, `principal_kind` (`user` or `application`) and `principal_id` are the initiator; `targets` (id, type, display name, user principal name) are what was changed. `source_ip` is the initiator's address when the record has one. An initiating application is not the person who ran it.

**Request is not effect.** `outcome` is the record's `result` (`outcome_detail` keeps it with `result_reason`, as written); `unknown` means it said neither success nor failure. A success shows the directory accepted the operation, not that a token, session or resource access changed.

**Modified properties** (`modified_properties`: target, name, old and new value) are the before and after of one target. The values are sensitive text, often JSON written as a string: a property named like a secret has both values withheld, the rest go through the credential rules, and `values_of_modified_properties_are_sensitive` is set. Read an old value as the previous state only when the record gives one.

**Rows that share a `correlation_id`** may belong to one operation. Keep `event_id`, `category`, `operation_type` and `logged_by_service` with each, and cite the file, record and line (`locator`). Delegated grants, application roles and workload credentials are different objects; a row says which it touched, not what it allows.

**A snapshot of the directory** is an observation at its collection time; a change needs an earlier state or these rows.

**Does not show:** that the initiator was the account's owner; that a change took effect or was used; changes the directory did not log; a complete export.

**Sensitive output:** names and addresses are personal data; run the job with `secret_output: true` when `write_values` is wanted. Report an object id in full, a secret never.
