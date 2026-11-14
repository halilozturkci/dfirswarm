---
id: m365/unified-audit-log
title: Microsoft 365 unified audit exports
when: Supplied Purview audit records need workload-specific interpretation and source-record correlation.
needs: [logs/what-exists]
card: ual_parse {"path": "<export>", "notable_only": true}: read status, coverage, pagination_markers first; count distinct Id. audit_data is the evidence. No zone is UTC only with {"assume_utc": true} per the export's documentation. An operation names a record, not an effect: MailItemsAccessed is not reading or exfiltration. Does not show: a human act, completeness of auditing.
tools: [ual_parse]
requires_host: []
---

Use when you hold unified audit log exports (portal or PowerShell CSV, native JSON, Graph records) and must say what was done in a workload, by which account. Not for sign-in analysis (`entra/signins`), mailbox configuration, or message delivery (no reader here). Offline: never authenticate to the tenant.

**What it is.** Purview audit gathers several workloads' activity, replaces none of their own logs, and one record can summarise several actions. Establish workload, record type, audit configuration, licence coverage and export method before interpreting a quiet period. Filter on `record_type` (number or name) and `operations` (exact names; `notable_only` keeps rule, forwarding, permission, consent, role and sharing ones), not free text; unmatched values are reported.

**Read the coverage `ual_parse` returns first.** `status` complete means every row was read. Failed files, rejected rows and unreadable `AuditData` payloads are counted apart (`coverage`, `file_census`, `rejected_records`). `pagination_markers`: one page of more, or fewer rows than the export's `ResultCount`. Overlapping searches repeat records: count distinct `Id`. Summary tables describe the matched records; `operations_all_rows` every row.

**`audit_data` is the evidence.** The whole payload is kept as written (`Name`/`Value`, `NewValue`/`OldValue`, duplicate parameter names) beside the lifted fields: read it for any decisive field. Cite the record `Id`; with none, say so and cite file, record and line.

**Time.** `time_status` says how each time was read. No zone is not UTC unless `assume_utc` was set on the export's own documentation. `03/04/2026` needs a `date_order` (or unambiguous rows prove one: `date_conventions`). `since`/`until` exclude and count rows whose time could not be read, no_zone included.

**Operations name a record, not an effect.** Inspect actor, target, result and changed properties for rules, forwarding, permissions, sharing and consent records. `SharingSet` is a sharing change, not outside access. A service principal's creation is not a consent or grant. `MailItemsAccessed` is not a person reading, or exfiltration: read `MailAccessType`, `OperationCount` and `Folders` as written. Aggregation and duplicate suppression can apply: check the export's schema before reading a quiet period as absence. `ClientIP` is the address the provider saw, often a proxy or carrier: pair it with sign-ins.

**Does not show:** a human act; completeness of auditing; what an operation changed beyond its recorded properties.

**Sensitive output:** parameters and properties can hold secrets. Run it as a job with `secret_output: true` (credential-named and -shaped values withheld; originals to `ual-values.jsonl` only with `write_values`).
