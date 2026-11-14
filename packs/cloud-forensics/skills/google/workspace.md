---
id: google/workspace
title: Google Workspace exported audit evidence
when: Supplied Google Workspace logs concern account access, administration, OAuth grants, Drive or Gmail.
needs: [logs/what-exists]
card: signin_analyse {"path": "<login activities>"} reads Workspace login activities only: another application's activity is rejected and counted; read it with cloud_normalise {"path": "<activities>", "provider": "workspace"}. A login row is not every session or token use. pagination_markers make the export partial. A time with no zone fails unless assume_utc is set on the export's documentation. Does not show: a person behind a login, that a grant was used.
tools: [signin_analyse, cloud_normalise]
mentions: [cloudtrail_parse]
requires_host: []
---

Use when you hold Google Workspace exports (login, admin, OAuth and token, Drive, Groups, mobile, Gmail) and must say what they show about access or activity. Not for Google Cloud audit logs, a different source (`gcp/audit-logs`), nor grants, delegation, sharing or forwarding detail (`google/workspace-access`). Offline: never authenticate to the tenant.

**Inventory each source on its own** (`logs/what-exists`, `logs/sources`): edition and privileges, filters, collection interval, pages, excluded or unsupported events, failures. Missing coverage limits a particular question; look at the other supplied sources before answering not determinable.

**The login parser.** `signin_analyse` reads Reports API login activities (each nested event one event, activity id and position kept) and flat login CSV. It rejects, counted and named, an activity whose `id.applicationName` is not login; a login row is not every session, token use or resource access. Check its field mapping against the original export. `cloudtrail_parse` (AWS) is never used here.

**Admin, Drive and token activities.** `cloud_normalise` (provider `workspace`) reads Reports API activities of any application, one row per event, with the whole `parameters` bag and `before_after` pairs. Names come from the record, unchecked against Google documentation: confirm one against the export.

**One API page is not an acquisition.** A next page (`pagination_markers`) makes it partial. For overlapping exports and late events, compare what was supplied and keep each cited event's activity id, record and line.

**What each shows.** Login events show authentication activity; admin events supported administrative actions; Drive events access and changes, subject to event coverage; OAuth and token events grant and application activity, by event name and parameters. Gmail log events, message-level exports and a BigQuery export have different schemas and different limits: say which one you hold. Verify availability and retention from the supplied collection records, not from a rule about editions.

**Time and zone.** Quote the time with its zone; one with no zone fails unless `assume_utc` is set on the export's own documentation.

**Does not show:** a person behind a login; that a grant was used; that a sharing or forwarding setting caused a transfer or a delivery.

**Sensitive output:** logins carry user names, addresses and devices; a value named or shaped like a credential is withheld, other secrets are not recognised. Run as a `secret_output: true` job when the export is sensitive. Never test or replay a recovered token or key.
