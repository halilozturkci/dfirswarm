---
id: google/workspace-access
title: Workspace grants, delegation, sharing and forwarding
when: You must reconstruct delegated access, Drive sharing or mailbox forwarding from Workspace evidence.
needs: [logs/what-exists]
tools: []
requires_host: []
---

Use when Workspace evidence must answer who holds delegated access, what was shared outside, or where mail was forwarded. Not for logins (`google/workspace`) or for revocation and containment (`identity/tokens`).

**Reconstruct delegated access from what was supplied.** No reader of token, Drive or admin events is in this pack: read the export as supplied and cite its file, record and position. Correlate OAuth grant and revocation events with any exported application or grant inventory, the scopes, client ids, administrative delegation settings and later resource activity. Domain-wide delegation and Apps Script authorisation are separate state: a token audit export is not an inventory of every durable access. `https://mail.google.com/` is broad Gmail authorisation, and a grant is not use. Missing exports are an acquisition ask through the case workflow; never query the tenant or test a recovered token.

**Separate exposure, access and transfer.** Look at external sharing, visibility changes, shared-drive membership, ownership changes, downloads and sync by file id and the event's actor and recipient context. A sharing change shows a recorded permission change, not that anyone retrieved the file. A download shows an access, not intent.

**Forwarding and filters.** State apart what was configured, what access was observed and what delivery or transfer was established. A configured forward is not evidence it ran; do not assume every user-created filter has an administrator audit event; correlate change records with message-delivery evidence where it exists.

**Record** for each finding: the event name and parameters, the actor, the target (file id, user, application, client id), the scopes, the time with its zone, and the source record's id and position.

**Does not show:** that a grant, share or forward was used; the state of any setting after the last supplied record.

**Sensitive output:** client secrets and tokens are secrets: place, type and what they grant go in the ledger, never the value or a hash; client and grant ids are identifiers, cited in full. A job that prints raw token events runs with `secret_output: true`.
