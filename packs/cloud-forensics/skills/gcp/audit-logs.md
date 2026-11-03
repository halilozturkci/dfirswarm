---
id: gcp/audit-logs
title: Cloud Audit Log entries
when: Supplied Cloud Audit Log entries must say which principal called which method on which resource.
needs: [logs/what-exists]
tools: [cloud_normalise]
requires_host: []
---

Use when you hold Cloud Audit Log entries (Admin Activity, Data Access, System Event, Policy Denied) and must say who called what, from where, with what result. Not for Workspace audit (`google/workspace`) or for Kubernetes API audit (`kubernetes/audit`). Offline: supplied exports only; never authenticate to the project.

**Read the coverage `cloud_normalise` returns first.** `status` is complete only if every entry was read and became a row; an entry that is not an audit log entry is in `rejected.jsonl` with its reason. `pagination_markers` names a `nextPageToken` whose page was not supplied.

**The four logs are different evidence.** `log_type` is `admin_activity`, `data_access`, `system_event` or `policy_denied`, read from `log_name`. A missing Data Access entry does not show nothing was read: whether that log was on for the service, its exemptions, the sinks, the exclusion filters and the log bucket's retention come from supplied settings, never from memory of a default.

**Principal and delegation.** `principal` is `authenticationInfo` (`principal_kind` says which field), and `delegation_chain` keeps every hop of a service account's delegation in order: the first party or user who started the chain is not the last service account. A service account name is not a person.

**Fields that carry the case:** `service`, `action` (the method), `resource` (the resource name), `tenant` (the project, organisation or folder), `resource_type` and `resource_labels`, `authorization` (the permission and whether it was granted), `source_ip`, `user_agent`, `operation` (the first and last entries of a long-running call), `event_id` (the `insertId`).

**Two times.** `time_raw` is the entry's `timestamp`, `receive_time_raw` when Cloud Logging received it; a late receive time is delivery, not the event. Count distinct `event_id` when exports overlap: duplicates are annotated and kept.

**Outcome.** `outcome` is `failure` for a non-zero `status.code`, `success` for code 0 or an empty status, and `unknown` when the entry has no status (`outcome_basis` says which). A permission-denied entry is an attempt, not a change.

**Does not show:** a person; that a call took effect or that data left; what the project did not log; a complete export.

**Sensitive output:** request and response fields can hold secrets. Run the tool as a job with `secret_output: true`; it withholds credential-named and credential-shaped values and writes originals only with `write_values`. Other secrets are not recognised.
