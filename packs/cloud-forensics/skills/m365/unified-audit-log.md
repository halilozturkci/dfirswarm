---
id: m365/unified-audit-log
title: Microsoft 365 unified audit exports
when: Supplied Purview audit records need workload-specific interpretation and source-record correlation.
needs: [logs/what-exists]
tools: [ual_parse]
requires_host: []
---

Use when you hold unified audit log exports (portal or PowerShell CSV, native JSON, Graph records) and must say what was done in a workload and by which account. Not for sign-in analysis (`entra/signins`), mailbox configuration, or message delivery (no reader here). Offline: supplied exports only; never authenticate to the tenant.

**What it is.** Purview audit gathers activity from several workloads; it does not replace each workload's own logs, and one record can summarise more than one action. Establish workload, record type, audit configuration, licence coverage and export method before interpreting a quiet period. Filter on `record_type` (number or name) and `operations` (exact names: `operations_all_rows` lists every one held; `notable_only` keeps rule, forwarding, permission, consent, role and sharing ones), not on free text; unmatched filter values are reported.

**Read the coverage `ual_parse` returns first.** `status` is complete only if every row was read. Failed files, rejected rows and unreadable `AuditData` payloads are separate counts (`coverage`, `file_census`, `rejected_records`). `pagination_markers` mean one page of more, or fewer rows than the export's own `ResultCount`. Overlapping searches repeat records and every copy is kept: count distinct `Id`. The summary tables describe the matched records; `operations_all_rows` is every row.

**`audit_data` is the evidence.** The tool lifts fields out of it and keeps the whole payload as written, with `Name`/`Value`, `NewValue`/`OldValue` and duplicate parameter names intact. Read the original for any decisive field. Cite the record `Id`; when the export has none, say so and cite file, record and line, never an invented id.

**Time.** `time_status` says how each time was read. A time with no zone is not UTC unless `assume_utc` was set on the export's own documentation. `03/04/2026` needs a `date_order` (or the file's unambiguous rows prove one, reported in `date_conventions`). A `since` or `until` filter excludes rows whose time could not be read, a no_zone time included, and counts them.

**Operations name a record, not an effect.** Inspect actor, target, result and changed properties for rules, forwarding, permissions, sharing and consent records. `SharingSet` records a sharing change, not that anyone outside got access. A service principal's creation is not a consent or a permission grant. `MailItemsAccessed` does not show a person read the content, or exfiltration: read `MailAccessType`, `OperationCount` and `Folders` as written. Aggregation and duplicate suppression can apply: check the schema the export carries before treating a quiet period as absence. `ClientIP` is the address the provider saw, often a proxy or carrier; pair it with sign-in evidence.

**Does not show:** a human act; completeness of auditing; what an operation changed beyond its recorded properties.

**Sensitive output:** parameters and properties can hold secrets. Run the tool as a job with `secret_output: true`; it withholds credential-named and credential-shaped values and writes originals to `ual-values.jsonl` only with `write_values`.
