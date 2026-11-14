---
id: google/workspace-access
title: Workspace grants, delegation, sharing and forwarding
when: Reconstruct delegated access, Drive sharing or mail forwarding from Workspace evidence.
needs: [logs/what-exists]
card: cloud_normalise {"path": "<Reports API activities>", "provider": "workspace"}: one row per event with parameters, parameters_by_name, before_after and topic_hints (this tool's own words, not Google's classification): read parameter names from the export and cite file, record and line. A token audit export is not an inventory of durable access; domain-wide delegation and Apps Script authorisation are separate state. A grant is not use, a sharing change is not a retrieval, a configured forward is not evidence it ran. Never test a recovered token. Does not show: that a grant, share or forward was used; a setting's state after the last record.
tools: [cloud_normalise]
requires_host: []
---

Use when Workspace evidence must answer who holds delegated access, what was shared outside, or where mail was forwarded. Not for logins (`google/workspace`) or for revocation and containment (`identity/tokens`).

**Reconstruct delegated access from what was supplied.** `cloud_normalise` (provider `workspace`) reads token, Drive and admin activities, one row per event with the whole `parameters` bag, `parameters_by_name`, `before_after` and `topic_hints` (words from this tool's own list, not Google's classification; the documentation was not checked): cite the row's file, record and line, and read the parameter names from the export. Correlate OAuth grant and revocation events with any exported application or grant inventory, the scopes, client ids, administrative delegation settings and later resource activity. Domain-wide delegation and Apps Script authorisation are separate state: a token audit export is not an inventory of every durable access. `https://mail.google.com/` is broad Gmail authorisation, and a grant is not use. Missing exports are an acquisition ask through the case workflow; never query the tenant or test a recovered token.

**Separate exposure, access and transfer.** Look at external sharing, visibility changes, shared-drive membership, ownership changes, downloads and sync by file id and the event's actor and recipient context. A sharing change shows a recorded permission change, not that anyone retrieved the file. A download shows an access, not intent.

**Forwarding and filters.** State apart what was configured, what access was observed and what delivery or transfer was established. A configured forward is not evidence it ran; do not assume every user-created filter has an administrator audit event; correlate change records with message-delivery evidence where it exists.

**Record** for each finding: the event name and parameters, the actor, the target (file id, user, application, client id), the scopes, the time with its zone, and the source record's id and position.

**Does not show:** that a grant, share or forward was used; the state of any setting after the last supplied record.

**Sensitive output:** client secrets and tokens are secrets: place, type and what they grant go in the ledger, never the value or a hash; client and grant ids are identifiers, cited in full. A job that prints raw token events runs with `secret_output: true`.
