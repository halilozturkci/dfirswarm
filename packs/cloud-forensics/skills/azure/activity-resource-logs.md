---
id: azure/activity-resource-logs
title: Azure Activity log, resource logs and Entra
when: Supplied Azure Activity log records must say what was done to which resource.
needs: [logs/what-exists]
card: cloud_normalise {"path": "<export>", "provider": "azure"}: portal CSV and resource or data-plane logs land in rejected.jsonl: read them in a recorded job. A Started or Accepted row is outcome unknown; its completion is another row of the same correlation_id; read sub_status before a failure. Does not show: data-plane access, a person, that a Succeeded operation still holds.
tools: [cloud_normalise]
requires_host: []
---

Use when you hold Azure Activity log records, resource or data-plane logs, diagnostic settings or Entra logs and must say what was done to which resource, with what answer. Not for sign-ins (`entra/signins`), directory changes (`entra/directory-audit`) or the M365 audit log (`m365/unified-audit-log`). Offline: never authenticate to the subscription.

**Read the coverage `cloud_normalise` returns first.** It reads Activity log records with `provider` `azure` (JSON, lines, or a CSV headed by the field names). Field names are not checked against Azure documentation; the portal's own CSV layout is not read (`rejected.jsonl`). `status` complete means every record was read; `pagination_markers` names a next page not supplied.

**Three planes, three sources.** The Activity log is the control plane: operations on resources (`action`, `resource`, `category`). Resource and data-plane logs are other exports, sent by diagnostic settings; this tool has no adapter for them (`rejected.jsonl`, with the reason): read them in a recorded job and say so. Entra is the identity plane (`entra/signins`, `entra/directory-audit`). A control-plane row does not show data-plane access, and a missing data-plane log does not show none.

**Scope and identity.** `tenant` is the subscription read from the resource id. `resource` and `authorization_scope` are separate fields printed as written: compare them, never assume one is the other. `principal` is the caller as written; `authorization_action` and `authorization_detail` are what the record names; `claims` is kept whole and sensitive. `source_ip` comes from `http_request`.

**Start and completion.** `lifecycle` is the status word; `status` (when the record's status is an object) and `sub_status` are kept as written: read `sub_status` before calling a row a failure. A Started or Accepted row has `outcome` `unknown`, never success; its completion is another row with the same `correlation_id`, and rows are never merged. A start with no completion in the set is an open question, not a failure. `time_raw` is the event time, `submission_time_raw` the submission.

**History of diagnostic settings.** Whether resource logs existed, and where they went, comes from the settings' history: look for changes among these rows by the setting's resource id (unchecked against Azure documentation). A snapshot is state when collected.

**Does not show:** a person; that a Succeeded operation still holds; data-plane access without the resource logs; what was not logged or exported.

**Sensitive output:** `claims`, `properties` and `http_request` can hold secrets: run it as a job with `secret_output: true` (credential-named and -shaped values withheld; originals only with `write_values`; other secrets not recognised).
